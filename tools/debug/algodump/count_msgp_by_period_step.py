#!/usr/bin/env python3
"""
Analyze caching effectiveness for P (PK) and P1S (signature) values in Algorand votes.

Works whether the file is:
  • a stream of msgpack objects      OR
  • one big array / map holding them.

The script simulates different cache sizes to determine hit rates and overall effectiveness.
Understands both map- and array-encoded structs produced by github.com/tinylib/msgp.
"""
from __future__ import annotations
import argparse, io, pathlib, msgpack, hashlib
from collections import Counter, namedtuple

Key = namedtuple("Key", ["tag", "rnd", "pk", "signature"])

# Cache simulator classes
class LRUCache:
    """Simple LRU cache implementation"""
    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = {}
        self.lru = []
        self.hits = 0
        self.misses = 0
    
    def get(self, key):
        if key in self.cache:
            # Update LRU status
            self.lru.remove(key)
            self.lru.append(key)
            self.hits += 1
            return self.cache[key]
        self.misses += 1
        return None
    
    def put(self, key, value):
        if key in self.cache:
            # Update existing key
            self.lru.remove(key)
        elif len(self.cache) >= self.capacity:
            # Evict least recently used item
            lru_key = self.lru.pop(0)
            del self.cache[lru_key]
        
        self.cache[key] = value
        self.lru.append(key)
    
    def hit_rate(self):
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0

# --------------------------------------------------------------------------- helpers

def _as_str(tag_raw):
    return tag_raw.decode("ascii", "replace") if isinstance(tag_raw, (bytes, bytearray)) else str(tag_raw)

def _get_period_step_from_rawvote(rawvote):
    """
    rawVote = {"per":…, "step":…}                     (map-form)
    """
    return rawvote.get(b"per"), rawvote.get(b"step")

def _decode_vote(obj):
    """
    unauthenticatedVote = {"r": rawVote, …}     (map)
    Extract round number, sender address, public key (p), and signature (p1s)
    """
    try:
        # Get round number and sender address
        raw_vote = obj.get(b"r")
        rnd = raw_vote.get(b"rnd")
        snd_bytes = raw_vote.get(b"snd")
        snd_hex = snd_bytes.hex() if snd_bytes else None
        
        # Get public key and signature as bytes (for direct comparison) and hex (for display)
        pk_bytes = obj.get(b"sig").get(b"p")
        pk_hex = pk_bytes.hex()
        
        sig_bytes = obj.get(b"sig").get(b"p1s")
        sig_hex = sig_bytes.hex()
        
        return rnd, snd_bytes, snd_hex, pk_bytes, sig_bytes, pk_hex, sig_hex
    except Exception as e:
        print(f"Error decoding vote: {e}")
        return None, None, None, None, None, None, None

def extract_vote_data(tag: str, blob: bytes):
    """
    Try to extract round, sender, pk, and signature from an AV or PP blob.
    Returns (None, None, None, None, None, None, None) on failure.
    """
    if tag not in ("AV", "PP"):
        return None, None, None, None, None, None, None
    
    try:
        obj = msgpack.unpackb(blob, raw=True, strict_map_key=False)
    except Exception as e:
        print(f"Error unpacking blob for tag {tag}: {e}")
        return None, None, None, None, None, None, None

    if tag == "AV":
        return _decode_vote(obj)

    if tag == "PP":
        prior_vote = obj.get(b"pv")
        if prior_vote:
            return _decode_vote(prior_vote)

    return None, None, None, None, None, None, None

# --------------------------------------------------------------------------- StoredMessage walker

def process_stored(tag_raw, blob: bytes, counter: Counter, pk_values: list, sig_values: list):
    tag = _as_str(tag_raw)
    rnd, pk_bytes, sig_bytes, pk_hex, sig_hex = extract_vote_data(tag, blob)
    
    if pk_bytes and sig_bytes:
        # Count occurrences of each round/pk/signature combination
        counter[Key(tag, rnd, pk_hex, sig_hex)] += 1
        
        # Also track individual PK and signature values
        if pk_bytes not in pk_values:
            pk_values.append(pk_bytes)
        if sig_bytes not in sig_values:
            sig_values.append(sig_bytes)

def walk(node, counter: Counter, pk_values: list, sig_values: list, pk_cache=None, sig_cache=None):
    """
    Recursively search for StoredMessages:
      • dict form  {"t":tag, "d":blob}
      • array form [tag, blob]
    
    Also simulates cache lookups if caches are provided.
    """
    if isinstance(node, dict):
        if "t" in node and "d" in node:
            # Process this message and update cache stats
            process_message(node["t"], node["d"], counter, pk_values, sig_values, pk_cache, sig_cache)
            return
        for v in node.values():
            walk(v, counter, pk_values, sig_values, pk_cache, sig_cache)
    elif isinstance(node, list):
        if len(node) == 2 and isinstance(node[1], (bytes, bytearray)):
            # Process this message and update cache stats
            process_message(node[0], node[1], counter, pk_values, sig_values, pk_cache, sig_cache)
            return
        for v in node:
            walk(v, counter, pk_values, sig_values, pk_cache, sig_cache)

# This function is no longer needed with the new implementation

# --------------------------------------------------------------------------- file handling

def iter_top_level(raw: bytes):
    """
    Yield top-level msgpack objects.
    Detects stream vs single-wrapper automatically.
    """
    unpacker = msgpack.Unpacker(io.BytesIO(raw), raw=False)
    items = list(unpacker)
    if len(items) > 1:
        yield from items                       # stream
    elif items:
        yield items[0]                         # single wrapper
    else:
        yield msgpack.unpackb(raw, raw=False)  # fallback

# This function is replaced by logic in main()

def extract_all_messages(node, messages):
    """Extract all stored messages from a node"""
    if isinstance(node, dict):
        if "t" in node and "d" in node:
            messages.append((node["t"], node["d"]))
            return
        for v in node.values():
            extract_all_messages(v, messages)
    elif isinstance(node, list):
        if len(node) == 2 and isinstance(node[1], (bytes, bytearray)):
            messages.append((node[0], node[1]))
            return
        for v in node:
            extract_all_messages(v, messages)

# --------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--no-pp", action="store_true",
                   help="Ignore votes in PP messages (only process AV messages)")
    ap.add_argument("--cache-sizes", type=str, default="2,4,8,16,32,64,128,256,512,1024",
                   help="Comma-separated list of cache sizes to simulate")
    ap.add_argument("files", nargs="+")
    ns = ap.parse_args()
    
    # For histogram of avg msgs per round
    sender_msgs_per_round = []
    msgs_per_round_hist = Counter()
    
    # Parse cache sizes
    cache_sizes = [int(s) for s in ns.cache_sizes.split(',')]
    
    # Counters and collections
    counter = Counter()
    
    # First, extract ALL messages from all files
    all_messages = []
    all_pk_values = set()
    all_sig_values = set()
    
    # To detect exact duplicate messages
    message_hash_counts = Counter()  # Count messages by their hash
    original_blobs = {}  # Store original blobs by hash
    
    # Track sender-specific data for analyzing effectiveness
    # Format: {sender_hex: {round: [(pk_bytes, sig_bytes, file_order)]}}  
    sender_data = {}
    
    for fp in ns.files:
        path = pathlib.Path(fp)
        if ns.debug:
            print(f"Reading {path.name}...")
        raw = path.read_bytes()
        # Extract messages
        file_messages = []
        for top in iter_top_level(raw):
            extract_all_messages(top, file_messages)
            
        # Process them to count unique values
        file_count = 0
        for msg_index, (tag_raw, blob) in enumerate(file_messages):
            tag = _as_str(tag_raw)
            
            # Skip PP messages if --no-pp flag is set
            if ns.no_pp and tag == "PP":
                continue
                
            # Use a proper hash function for byte strings that doesn't change between runs
            msg_hash = hashlib.sha256(blob).hexdigest()
            message_hash_counts[msg_hash] += 1
            
            # Store original blob if we haven't seen it before
            if msg_hash not in original_blobs:
                original_blobs[msg_hash] = blob
                
            rnd, snd_bytes, snd_hex, pk_bytes, sig_bytes, pk_hex, sig_hex = extract_vote_data(tag, blob)
            if pk_bytes and sig_bytes and snd_hex:
                counter[Key(tag, rnd, pk_hex, sig_hex)] += 1
                file_count += 1
                all_pk_values.add(pk_bytes)
                all_sig_values.add(sig_bytes)
                
                # Track sender-specific data for effectiveness analysis
                if snd_hex not in sender_data:
                    sender_data[snd_hex] = {}
                if rnd not in sender_data[snd_hex]:
                    sender_data[snd_hex][rnd] = []
                
                # Store (pk, sig, file_index, message_index)
                sender_data[snd_hex][rnd].append((pk_bytes, sig_bytes, len(all_messages), msg_index))
                
                # Add to the global list
                all_messages.append((tag, rnd, snd_hex, pk_bytes, sig_bytes, msg_hash))
            
        if ns.debug:
            print(f"{path.name}: StoredMessages = {file_count}")
    
    # Count exact duplicates
    exact_duplicate_count = sum(count - 1 for count in message_hash_counts.values() if count > 1)
    unique_message_count = len(message_hash_counts)
    total_messages_processed = sum(message_hash_counts.values())
    duplicate_distribution = Counter()
    for count in message_hash_counts.values():
        if count > 1:
            duplicate_distribution[count] += 1
    
    # Calculate messages per round for each sender
    for snd_hex, rounds in sender_data.items():
        # Count how many rounds this sender appears in
        round_count = len(rounds)
        
        # Count how many total messages this sender has
        total_msgs = sum(len(msgs) for msgs in rounds.values())
        
        # Calculate average messages per round for this sender
        if round_count > 0:
            avg_msgs_per_round = total_msgs / round_count
            sender_msgs_per_round.append((snd_hex, avg_msgs_per_round, round_count, total_msgs))
            
            # Bin for histogram (round to nearest 0.25)
            hist_bin = round(avg_msgs_per_round * 4) / 4
            msgs_per_round_hist[hist_bin] += 1
    
    # Now simulate each cache size using all messages
    pk_caches = {}
    sig_caches = {}
    for size in cache_sizes:
        # Create caches for this size
        pk_cache = LRUCache(size)
        sig_cache = LRUCache(size)
        
        # Process all messages
        for msg_data in all_messages:
            # Unpack the message data (now includes msg_hash)
            tag, rnd, snd_hex, pk_bytes, sig_bytes, msg_hash = msg_data
            
            # PK cache lookup
            pk_cache.get(pk_bytes)
            pk_cache.put(pk_bytes, True)
            
            # Signature cache lookup
            sig_cache.get(sig_bytes)
            sig_cache.put(sig_bytes, True)
        
        # Store results
        pk_caches[size] = (pk_cache.hits, pk_cache.misses, pk_cache.hit_rate())
        sig_caches[size] = (sig_cache.hits, sig_cache.misses, sig_cache.hit_rate())
    
    # Analyze PK/signature reuse patterns (not sender-specific)
    # Track which PK/signature pairs appear multiple times and where
    pk_sig_usage = {}
    

    
    # Size parameters
    pk_size = 32  # public key size in bytes
    sig_size = 64  # signature size in bytes
    ref_size = 2   # reference size in bytes (uint16)
    
    # Process all messages to count occurrences of each PK/signature pair
    for msg_data in all_messages:
        # Unpack the message data (now includes msg_hash)
        tag, rnd, snd_hex, pk_bytes, sig_bytes, msg_hash = msg_data
        
        # Use the concatenated PK+sig as the key (since they're always used together)
        pk_sig_key = pk_bytes + sig_bytes
        
        if pk_sig_key not in pk_sig_usage:
            pk_sig_usage[pk_sig_key] = []
        
        # Record this usage with (round, sender, position in all_messages)
        pk_sig_usage[pk_sig_key].append((rnd, snd_hex, len(pk_sig_usage[pk_sig_key])))
    
    # Analyze the usage patterns
    unique_pairs = len(pk_sig_usage)
    reused_pairs = sum(1 for usages in pk_sig_usage.values() if len(usages) > 1)
    total_reuses = sum(len(usages) - 1 for usages in pk_sig_usage.values() if len(usages) > 1)
    
    # Count how many are reused across different rounds vs. same round
    same_round_reuses = 0
    diff_round_reuses = 0
    same_sender_reuses = 0
    diff_sender_reuses = 0
    
    # Track distribution of reuse counts
    reuse_count_hist = Counter()
    
    for pk_sig, usages in pk_sig_usage.items():
        if len(usages) <= 1:
            continue  # Skip pairs used only once
            
        # Count this in our histogram
        reuse_count_hist[len(usages)] += 1
        
        # Count reuses by round and sender
        rounds_seen = set()
        senders_seen = set()
        
        for rnd, snd, pos in usages:
            rounds_seen.add(rnd)
            senders_seen.add(snd)
        
        # Track if reuses are in same or different rounds
        if len(rounds_seen) == 1:
            same_round_reuses += 1
        else:
            diff_round_reuses += 1
            
        # Track if reuses are by same or different senders
        if len(senders_seen) == 1:
            same_sender_reuses += 1
        else:
            diff_sender_reuses += 1
    
    # Calculate potential bytes saved
    pk_bytes_saved = total_reuses * (pk_size - ref_size)
    sig_bytes_saved = total_reuses * (sig_size - ref_size)
    total_bytes_saved = pk_bytes_saved + sig_bytes_saved
    
    if not counter:
        print("No vote messages found."); return
    
    # Report overall statistics
    total_msgs = sum(counter.values())
    unique_pks = len(all_pk_values)
    unique_sigs = len(all_sig_values)
    total_senders = len(sender_data)
    
    print(f"\nProcessed {total_msgs} vote messages ({total_messages_processed} total)")
    print(f"Found {unique_message_count} unique message contents ({exact_duplicate_count} duplicates)")
    print(f"Found {unique_pks} unique PK values and {unique_sigs} unique signatures")
    print(f"Total unique senders: {total_senders}")
    
    # Print duplicate distribution
    print(f"\nDuplicate Message Distribution:")
    print(f"{'Count':>6} {'Messages':>10} {'Duplicates':>12}")
    print("-" * 35)
    total_dupes = 0
    for count, num_msgs in sorted(duplicate_distribution.items()):
        dupes = num_msgs * (count-1)
        total_dupes += dupes
        print(f"{count:>6} {num_msgs:>10} {dupes:>12}")
    print(f"{'Total':>6} {len(duplicate_distribution):>10} {total_dupes:>12}")
    
    # Calculate percentages
    duplicate_pct = exact_duplicate_count / total_messages_processed * 100 if total_messages_processed > 0 else 0
    print(f"\nExact duplicates: {exact_duplicate_count:,} of {total_messages_processed:,} messages ({duplicate_pct:.2f}%)")
    
    # Compare with PK/signature reuse
    print(f"PK/sig duplicates: {total_reuses:,} messages ({total_reuses/total_msgs*100:.2f}%)")
    print(f"Conclusion: {exact_duplicate_count == total_reuses}")
    if exact_duplicate_count == total_reuses:
        print("CONFIRMED: All PK/signature reuse comes from exact duplicate messages")
    else:
        print(f"Difference: {abs(exact_duplicate_count - total_reuses)} messages")
    
    # For each tag, count messages
    tag_counts = Counter()
    for key in counter.keys():
        tag_counts[key.tag] += counter[key]
    
    print("\nMessage counts by tag:")
    for tag, count in sorted(tag_counts.items()):
        print(f"{tag:>4}: {count:>8}")
    
    # Print PK/signature pair reuse analysis
    print(f"\nPK/Signature Pair Reuse Analysis:")
    print(f"Total unique PK/signature pairs: {unique_pairs}")
    print(f"Pairs used more than once: {reused_pairs} ({reused_pairs/unique_pairs*100:.2f}%)")
    print(f"Total reuse count: {total_reuses} ({total_reuses/total_msgs*100:.2f}% of messages)")
    
    # Analysis by round and sender
    print(f"\nReuse Pattern Analysis:")
    print(f"Pairs reused within same round: {same_round_reuses} ({same_round_reuses/reused_pairs*100:.2f}% of reused pairs)")
    print(f"Pairs reused across different rounds: {diff_round_reuses} ({diff_round_reuses/reused_pairs*100:.2f}% of reused pairs)")
    print(f"Pairs reused by same sender: {same_sender_reuses} ({same_sender_reuses/reused_pairs*100:.2f}% of reused pairs)")
    print(f"Pairs reused by different senders: {diff_sender_reuses} ({diff_sender_reuses/reused_pairs*100:.2f}% of reused pairs)")
    
    # Potential bytes saved through PK/signature caching
    total_pk_bytes = total_msgs * pk_size
    total_sig_bytes = total_msgs * sig_size
    pk_compression = pk_bytes_saved / total_pk_bytes * 100 if total_pk_bytes > 0 else 0
    sig_compression = sig_bytes_saved / total_sig_bytes * 100 if total_sig_bytes > 0 else 0
    bytes_saved_per_msg = total_bytes_saved / total_msgs if total_msgs > 0 else 0
    
    print(f"\nPotential Bytes Saved through PK/Signature Caching:")
    print(f"PK bytes saved: {pk_bytes_saved:,} of {total_pk_bytes:,} ({pk_compression:.2f}%)")
    print(f"Signature bytes saved: {sig_bytes_saved:,} of {total_sig_bytes:,} ({sig_compression:.2f}%)")
    print(f"Total bytes saved: {total_bytes_saved:,} bytes ({bytes_saved_per_msg:.2f} bytes/message)")
    
    # Distribution of reuse counts
    print(f"\nDistribution of PK/Signature Pair Reuse Counts:")
    print(f"{'Count':>6} {'Pairs':>10} {'%Total':>10}")
    print("-" * 30)
    
    # Get sorted reuse counts and display them
    reuse_counts = sorted(reuse_count_hist.items())
    for count, num_pairs in reuse_counts:
        print(f"{count:>6} {num_pairs:>10} {num_pairs/unique_pairs*100:>9.2f}%")
        
    # Histogram of senders by average messages per round
    print(f"\nDistribution of Senders by Avg Messages per Round:")
    print(f"{'Msgs/Round':>12} {'Senders':>10} {'%Total':>10}")
    print("-" * 35)
    
    # Create histogram with 0.25 buckets for avg msgs per round
    total_senders = len(sender_data)
    for msgs_per_round, count in sorted(msgs_per_round_hist.items()):
        print(f"{msgs_per_round:>12.2f} {count:>10} {count/total_senders*100:>9.2f}%")
        
    # Print some summary statistics about messages per round
    all_avg_msgs = [avg for _, avg, _, _ in sender_msgs_per_round]
    if all_avg_msgs:
        print(f"\nAverage Messages per Round Statistics:")
        print(f"Min: {min(all_avg_msgs):.2f} msgs/round")
        print(f"Max: {max(all_avg_msgs):.2f} msgs/round")
        print(f"Median: {sorted(all_avg_msgs)[len(all_avg_msgs)//2]:.2f} msgs/round")
        print(f"Mean: {sum(all_avg_msgs)/len(all_avg_msgs):.2f} msgs/round")
    
    # Print cumulative stats for most frequently reused pairs
    if reuse_counts:
        print(f"\nCumulative Impact of Most Reused Pairs:")
        print(f"{'Min Reuses':>12} {'Pairs':>10} {'Bytes Saved':>15} {'%Total Saved':>15}")
        print("-" * 60)
        
        # Calculate cumulative impacts
        sorted_counts = sorted(reuse_count_hist.keys(), reverse=True)
        for threshold in [2, 3, 5, 10, 20, 50, 100]:
            if threshold > max(sorted_counts):
                break
                
            pairs_above = sum(reuse_count_hist[c] for c in sorted_counts if c >= threshold)
            reuses_above = sum(reuse_count_hist[c] * (c-1) for c in sorted_counts if c >= threshold)
            bytes_saved = reuses_above * (pk_size + sig_size - ref_size)
            pct_saved = bytes_saved / total_bytes_saved * 100 if total_bytes_saved > 0 else 0
            
            print(f"{threshold:>12} {pairs_above:>10} {bytes_saved:>15,} {pct_saved:>14.2f}%")
    
    # Print PK cache effectiveness
    print(f"\nPK Cache Effectiveness:")
    print(f"{'Size':>6} {'Hits':>10} {'Misses':>10} {'Hit Rate':>10}")
    print("-" * 40)
    for size in sorted(cache_sizes):
        hits, misses, hit_rate = pk_caches[size]
        print(f"{size:>6} {hits:>10} {misses:>10} {hit_rate:>9.2f}%")
    
    # Print Signature cache effectiveness
    print(f"\nSignature Cache Effectiveness:")
    print(f"{'Size':>6} {'Hits':>10} {'Misses':>10} {'Hit Rate':>10}")
    print("-" * 40)
    for size in sorted(cache_sizes):
        hits, misses, hit_rate = sig_caches[size]
        print(f"{size:>6} {hits:>10} {misses:>10} {hit_rate:>9.2f}%")
    
    # Optionally display top 10 most common vote types
    if ns.debug:
        print(f"\nTop 10 most common vote types:")
        for (tag, rnd, pk, sig), cnt in counter.most_common(10):
            # Show truncated values for readability
            pk_short = pk[:8] + '...' if pk else 'None'
            sig_short = sig[:8] + '...' if sig else 'None'
            print(f"{tag:>4} Round:{rnd} PK:{pk_short} Sig:{sig_short} Count:{cnt}")


if __name__ == "__main__":
    main()

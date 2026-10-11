// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package dnssec

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestParseRootTrustAnchor(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	an1, err := makeRootTrustAnchor(rootAnchorXML)
	a.NoError(err)
	an2, err := MakeRootTrustAnchor()
	a.NoError(err)
	a.Equal(an1, an2)

	dss := an2.ToDS()
	a.Equal(3, len(dss))
	ksk2017 := dss[1]
	a.Equal("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", ksk2017.Digest)
	a.Equal(uint16(20326), ksk2017.KeyTag)
	a.Equal(uint8(8), ksk2017.Algorithm)
	a.Equal(uint8(2), ksk2017.DigestType)
	ksk2024 := dss[2]
	a.Equal("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16", ksk2024.Digest)
	a.Equal(uint16(38696), ksk2024.KeyTag)
	a.Equal(uint8(8), ksk2024.Algorithm)
	a.Equal(uint8(2), ksk2024.DigestType)

	_, err = makeRootTrustAnchor("not xml")
	a.Error(err)
}

// rootDNSKEYKSK2024 is the root zone DNSKEY RRset and its RRSIG as published after the
// 2026-10-11 root KSK rollover: signed only by KSK-2024 (key tag 38696).
var rootDNSKEYKSK2024 = []string{
	". 3420 IN DNSKEY 256 3 8 AwEAAcorNxNc9t0ue1ZenPjVMRujlQ2YLBJ0pR/4XMjHby9vr03cRxFSKnWpxeg5PL384D9VeqdS1bjrGyTsHtoagzI3NiXFd8sjHMOnZxu5pp/+UBIg7tasYgVMMdUiM1Yu/c+t30d1Qw/v6NYLNnOnywTu6HuUh7Y1sZRq/GZcrxLENXHQoyKpOrOr8R3+qd6wK69IKB80ZBZtkX9rdEqKJk+yYXjEZzZ0zkAFthmNgCreAoU9PVlU66dyOsaLjf3wKUlUm9SNOKs+tK6LuSmRbK6+1T/tPaRaMBSEuv2G6vXfnJ1uyMbGvtpRn/YDcvTjrp6DzE6XyF44QdwJ3oKx4ek=",
	". 3420 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	". 3420 IN DNSKEY 257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=",
	". 3420 IN RRSIG DNSKEY 8 0 172800 20261101000000 20261011000000 38696 . llXxlp+gWc4h/F9G8UPj3VXhNDQoZrco3Piivk7YMKS7pi8B+CBQHHPO/QNw+VfpNq7CtBDA6gxucyia1ZZx8yM0oLve7qJKgPuRVNnw5AOegtdxy+NKSy8rT6XNtCdM2gL9EmqKux+/JNATbZG2efGkVpHuirkq0Vs1bvYglVl6fvHbqoHpfjbnHVheuKpq+HvdsZOphoEJu74Y4lpYNBNTJijGgajnJ64AUMPbMfu76uLi68CcWKDGWhzCNeSwnSjK7CA6aKte5StW61Nuz0Nv8mvzqMX0epPQ7lXJ9Yc/685081BdzAYK3yMAfTOqL4EgluNZQAtAAh9bseJVyw==",
}

type staticRootQuerier struct {
	QueryWrapper
	rrSet []dns.RR
	rrSig []dns.RRSIG
}

func (q staticRootQuerier) QueryRRSet(ctx context.Context, domain string, qtype uint16) ([]dns.RR, []dns.RRSIG, error) {
	return q.rrSet, q.rrSig, nil
}

// TestRootKSK2024 checks that the embedded trust anchor validates the real root DNSKEY RRset
// signed by KSK-2024 only.
func TestRootKSK2024(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	var q staticRootQuerier
	for _, s := range rootDNSKEYKSK2024 {
		rr, err := dns.NewRR(s)
		a.NoError(err)
		if sig, ok := rr.(*dns.RRSIG); ok {
			q.rrSig = append(q.rrSig, *sig)
		} else {
			q.rrSet = append(q.rrSet, rr)
		}
	}
	a.Len(q.rrSig, 1)
	a.Equal(uint16(38696), q.rrSig[0].KeyTag)

	// within the RRSIG validity period
	now := time.Date(2026, time.October, 20, 0, 0, 0, 0, time.UTC)
	tz, cacheOutdated, err := makeTrustedZone(context.Background(), ".", trustedZone{}, q, now)
	a.NoError(err)
	a.False(cacheOutdated)
	a.Contains(tz.ksk, uint16(38696))
	a.Contains(tz.rrSig, uint16(38696))
}

from hands import protocol


def test_a_nonce_outlives_the_last_second_its_bearer_is_fresh():
    """Device clock 300 s ahead: first seen at relay time T-300, replayed at T+300."""
    ts = 1_800_000_000
    cache = protocol.NonceCache()
    assert protocol.fresh(ts, ts - 300) and cache.check_and_add("n", ts - 300)
    assert protocol.fresh(ts, ts + 300)
    assert not cache.check_and_add("n", ts + 300)
    assert not protocol.fresh(ts, ts + 301)


def test_nonce_cache_evicts_the_earliest_expiry_at_capacity():
    cache = protocol.NonceCache(ttl=10, max_entries=2)
    assert cache.check_and_add("later", 100)
    assert cache.check_and_add("earlier", 95)
    assert cache.check_and_add("next", 101)
    assert sorted(cache._entries) == ["later", "next"]
    assert cache.check_and_add("earlier", 102)
    assert len(cache._entries) == 2

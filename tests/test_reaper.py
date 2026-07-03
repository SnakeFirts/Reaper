import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from reaper import (
    normalize,
    normalize_core,
    check_dictionary,
    check_variants,
    detect_human_patterns,
    calculate_score,
    classify,
    mask_password,
)


# normalize() / normalize_core()
class TestNormalize:
    def test_basic_leetspeak(self):
        assert normalize("P4ssw0rd") == "password"

    def test_multiple_substitutions(self):
        assert normalize("h3ll0!") == "hello" + "i"  # "!" -> "i" al final

    def test_no_substitution_needed(self):
        assert normalize("hello") == "hello"

    def test_case_insensitive(self):
        assert normalize("PASSWORD") == "password"


class TestNormalizeCore:
    def test_preserves_numeric_suffix(self):
        assert normalize_core("P4ssw0rd123") == "password123"

    def test_preserves_year_suffix(self):
        assert normalize_core("Sh1b0ya2024") == "shiboya2024"

    def test_no_numeric_suffix_falls_back_to_normalize(self):
        assert normalize_core("P4ssw0rd") == normalize("P4ssw0rd")

    def test_pure_digits_password(self):
        result = normalize_core("123456")
        assert result == normalize("123456")


# check_dictionary() / check_variants()
class TestDictionaryChecks:
    @pytest.fixture
    def dictionaries(self):
        return {
            "common": {"password", "qwerty"},
            "xato": {"password123", "letmein"},
        }

    def test_exact_match(self, dictionaries):
        hits = check_dictionary("password", dictionaries=dictionaries)
        assert "common" in hits

    def test_no_match(self, dictionaries):
        hits = check_dictionary("xJ9$kL2!qP", dictionaries=dictionaries)
        assert hits == []

    def test_case_insensitive_match(self, dictionaries):
        hits = check_dictionary("PASSWORD", dictionaries=dictionaries)
        assert "common" in hits

    def test_variant_with_numeric_suffix_detected(self, dictionaries):
        is_variant, normalized, source = check_variants("P4ssw0rd123", dictionaries=dictionaries)
        assert is_variant is True
        assert normalized == "password123"
        assert source == "xato"

    def test_variant_without_suffix_still_detected(self, dictionaries):
        is_variant, normalized, source = check_variants("P4ssw0rd", dictionaries=dictionaries)
        assert is_variant is True
        assert normalized == "password"

    def test_no_variant_match(self, dictionaries):
        is_variant, normalized, source = check_variants("xJ9$kL2!qP", dictionaries=dictionaries)
        assert is_variant is False
        assert source is None


# detect_human_patterns()
class TestDetectHumanPatterns:
    def test_character_repetition(self):
        assert any("repetition" in p.lower() for p in detect_human_patterns("aaa1234"))

    def test_simple_sequence(self):
        assert any("sequence" in p.lower() for p in detect_human_patterns("abc12345"))

    def test_common_prefix(self):
        assert any("prefix" in p.lower() for p in detect_human_patterns("admin2024"))

    def test_common_suffix(self):
        assert any("suffix" in p.lower() for p in detect_human_patterns("summer2024"))

    def test_no_patterns_for_random_password(self):
        assert detect_human_patterns("xJ9#kL2$qPwR") == []


# calculate_score() / classify()
class TestCalculateScore:
    def test_no_penalties_high_zxcvbn(self):
        score = calculate_score(dictionary_hits=[], hibp_count=0, patterns=[], is_variant=False, zx_score=4)
        assert score == 100

    def test_dictionary_hit_penalizes(self):
        base = calculate_score(dictionary_hits=[], hibp_count=0, patterns=[], is_variant=False, zx_score=4)
        with_hit = calculate_score(dictionary_hits=["common"], hibp_count=0, patterns=[], is_variant=False, zx_score=4)
        assert with_hit < base

    def test_hibp_penalty_scales_with_magnitude(self):
        # Regresion del bug de -40 fijo: mas apariciones en breaches
        # debe penalizar MAS, no lo mismo.
        low = calculate_score(dictionary_hits=[], hibp_count=1, patterns=[], is_variant=False, zx_score=4)
        high = calculate_score(dictionary_hits=[], hibp_count=100_000, patterns=[], is_variant=False, zx_score=4)
        assert high < low

    def test_hibp_none_means_no_penalty(self):
        no_lookup = calculate_score(dictionary_hits=[], hibp_count=None, patterns=[], is_variant=False, zx_score=4)
        assert no_lookup == 100

    def test_score_never_negative(self):
        score = calculate_score(
            dictionary_hits=["darkweb", "darkweb", "darkweb"],
            hibp_count=1_000_000,
            patterns=["a", "b", "c", "d"],
            is_variant=True,
            zx_score=0,
        )
        assert score >= 0

    def test_score_never_above_100(self):
        score = calculate_score(dictionary_hits=[], hibp_count=None, patterns=[], is_variant=False, zx_score=4)
        assert score <= 100


class TestClassify:
    @pytest.mark.parametrize("score,expected", [
        (0, "CRITICAL"),
        (20, "CRITICAL"),
        (21, "WEAK"),
        (40, "WEAK"),
        (41, "MODERATE"),
        (70, "MODERATE"),
        (71, "STRONG"),
        (90, "STRONG"),
        (91, "REAPER-CLASS"),
        (100, "REAPER-CLASS"),
    ])
    def test_boundaries(self, score, expected):
        assert classify(score) == expected


# mask_password()
class TestMaskPassword:
    def test_masks_middle_characters(self):
        assert mask_password("password") == "p******d"

    def test_short_password_fully_masked(self):
        assert mask_password("ab") == "**"
        assert mask_password("a") == "*"

    def test_empty_password(self):
        assert mask_password("") == ""

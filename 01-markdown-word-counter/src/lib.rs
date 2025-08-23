use regex::Regex;

/// Counts the amount of times a given word appears in a markdown text.
pub fn count_words(word: &str, contents: &str) -> u32 {
    let cleanup_matcher = Regex::new(r"([*_`~]+)").unwrap();
    let clean_contents = cleanup_matcher.replace_all(contents, "");

    let word_matcher_pattern = format!(r"\b{}\b", word);
    let word_matcher = Regex::new(&word_matcher_pattern).unwrap();

    word_matcher.find_iter(&clean_contents).count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_one_word() {
        let word = "abc";
        let contents = "123 abc 123";

        assert_eq!(1, count_words(word, contents));
    }

    #[test]
    fn counts_word_at_the_end() {
        let word = "abc";
        let contents = "123 abc";

        assert_eq!(1, count_words(word, contents));
    }

    #[test]
    fn counts_word_at_the_start() {
        let word = "abc";
        let contents = "abc 123";

        assert_eq!(1, count_words(word, contents));
    }

    #[test]
    fn counts_multiple_words() {
        let word = "abc";
        let contents = "abc abc abc abc";

        assert_eq!(4, count_words(word, contents));
    }

    #[test]
    fn counts_multiple_words_in_different_lines() {
        let word = "abc";
        let contents = "\
        123 abc 123
        abc 123 123
        123 123 abc";

        assert_eq!(3, count_words(word, contents));
    }

    #[test]
    fn counts_individual_words() {
        let word = "abc";
        let contents = "abc abcx abc zabcx";

        assert_eq!(2, count_words(word, contents));
    }

    #[test]
    fn counts_individual_words_with_markdown() {
        let word = "abc";
        let contents = "**abc** _abcx_  _abc_ `zabcx` `abc` ~~abc~~ **abc**x";

        assert_eq!(4, count_words(word, contents));
    }
}

use regex::Regex;

pub fn count_words(word: &str, contents: &str) -> u32 {
    let pattern = format!(r"\b{}\b", word);
    let matcher = Regex::new(&pattern).unwrap();

    matcher.find_iter(&contents).count() as u32
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
}

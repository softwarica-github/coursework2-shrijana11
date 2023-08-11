import unittest
from unittest.mock import patch
import eg 

class TestPasswordCracker(unittest.TestCase):
    @patch('builtins.input', side_effect=['3', 'abcd'])
    def test_brute_force_attack(self, mock_input):
        # The brute_force_attack function doesn't return anything, so we can only test its behavior
        eg.brute_force_attack(max_password_length=2, possible_characters="")

    def test_check_passwords(self):
        wordlist_file = 'word.txt'
        username_hash_file = 'username_hash.txt'
        hash_types = ['MD5']
        expected_results = [
           ('User1', 'SoftwaricaCollege123'),
           ('Ashley', '123456'),
           ('Jasmin', 'ABCD12345678')
       ]

        # Assuming you have a word.txt and username_hash (1).txt with appropriate data for testing
        results = eg.check_passwords(wordlist_file, username_hash_file, hash_types)
        self.assertEqual(results, expected_results)

if __name__ == '__main__':
    unittest.main()

import string
import math
import re
from datetime import datetime

# Reference data
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "abc123", "password1", "111111", "iloveyou",
    "admin", "welcome", "letmein", "monkey", "dragon", "football",
    "123123", "000000", "1q2w3e4r", "qwertyuiop", "sunshine"
}

# Common keyboard-walk patterns attackers try first.
KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcv", "qazwsx", "1qaz2wsx", "qwertyuiop"
]

COLOR = {
    "Weak": "\033[91m",        # red
    "Medium": "\033[93m",      # yellow
    "Strong": "\033[92m",      # green
    "Very Strong": "\033[96m", # cyan
    "reset": "\033[0m",
}


class PasswordStrengthChecker:
    """Encapsulates all password analysis logic in one place."""

    def __init__(self, password: str):
        self.password = password
        self.length = len(password)
        self.feedback = []
        self.score = 0          # out of 10
        self.max_score = 10
        self.entropy_bits = 0.0


    def _check_length(self):
        if self.length >= 12:
            self.score += 2
        elif self.length >= 8:
            self.score += 1
            self.feedback.append("Consider 12+ characters for stronger protection.")
        else:
            self.feedback.append("Too short — use at least 8 characters (12+ is better).")

    def _check_variety(self):
        has_lower = any(c in string.ascii_lowercase for c in self.password)
        has_upper = any(c in string.ascii_uppercase for c in self.password)
        has_digit = any(c in string.digits for c in self.password)
        has_symbol = any(c in string.punctuation for c in self.password)

        for present, tip in [
            (has_lower, "Add a lowercase letter."),
            (has_upper, "Add an uppercase letter."),
            (has_digit, "Add a number."),
            (has_symbol, "Add a symbol (e.g. ! @ # $ %)."),
        ]:
            if present:
                self.score += 1
            else:
                self.feedback.append(tip)

        return has_lower, has_upper, has_digit, has_symbol

    def _check_repeated_characters(self):
        # Flags things like "aaaa", "1111", "!!!!"
        if re.search(r"(.)\1{2,}", self.password):
            self.feedback.append("Avoid repeating the same character 3+ times in a row.")
            self.score -= 1

    def _check_sequential_patterns(self):
        lowered = self.password.lower()

        # Numeric or alphabetic runs like "1234", "abcd"
        sequences = "abcdefghijklmnopqrstuvwxyz0123456789"
        for i in range(len(sequences) - 3):
            chunk = sequences[i:i + 4]
            if chunk in lowered:
                self.feedback.append(f"Avoid sequential characters like \"{chunk}\".")
                self.score -= 1
                break

        # Keyboard-walk patterns
        for pattern in KEYBOARD_PATTERNS:
            if pattern in lowered:
                self.feedback.append(f"Avoid keyboard patterns like \"{pattern}\".")
                self.score -= 1
                break

    def _check_common_password(self):
        if self.password.lower() in COMMON_PASSWORDS:
            self.feedback = ["This password appears in known leaked/common password lists. "
                              "Choose something unique — this overrides all other checks."]
            self.score = 0
            return True
        return False

    def _calculate_entropy(self, has_lower, has_upper, has_digit, has_symbol):
        """
        Entropy estimates brute-force resistance in bits:
            entropy = length * log2(pool_size)
        Bigger character pool + longer password = exponentially more guesses needed.
        """
        pool_size = 0
        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digit:
            pool_size += 10
        if has_symbol:
            pool_size += len(string.punctuation)

        if pool_size == 0 or self.length == 0:
            self.entropy_bits = 0.0
        else:
            self.entropy_bits = round(self.length * math.log2(pool_size), 1)


    def analyze(self):
        """Run every check and return (strength, score, entropy_bits, feedback)."""
        if self._check_common_password():
            return "Weak", 0, 0.0, self.feedback

        variety = self._check_variety()
        self._check_length()
        self._check_repeated_characters()
        self._check_sequential_patterns()
        self._calculate_entropy(*variety)

        # Clamp score into a sensible range
        self.score = max(0, min(self.score, self.max_score))

        if self.entropy_bits >= 60 and self.score >= 7:
            strength = "Very Strong"
        elif self.entropy_bits >= 45 and self.score >= 6:
            strength = "Strong"
        elif self.score >= 4:
            strength = "Medium"
        else:
            strength = "Weak"

        if not self.feedback:
            self.feedback.append("Great job! This password meets all the criteria.")

        return strength, self.score, self.entropy_bits, self.feedback



def suggest_strong_password(length: int = 14) -> str:
    """Generates a random strong password using Python's secrets module
    (cryptographically secure, unlike random.choice)."""
    import secrets
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))



def display_result(password: str):
    checker = PasswordStrengthChecker(password)
    strength, score, entropy, feedback = checker.analyze()
    color = COLOR.get(strength, "")
    reset = COLOR["reset"]

    print("\n" + "=" * 48)
    print(f"Password           : {'*' * len(password)}")
    print(f"Strength           : {color}{strength}{reset}  (score: {score}/10)")
    print(f"Estimated entropy  : {entropy} bits")
    print("Feedback:")
    for tip in feedback:
        print(f"  - {tip}")
    print("=" * 48)


def batch_check(filepath: str, report_path: str = "password_report.txt"):
    """Reads one password per line from filepath and writes a summary report."""
    with open(filepath, "r", encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]

    lines = [f"Password Strength Report — generated {datetime.now():%Y-%m-%d %H:%M}\n"]
    for pw in passwords:
        checker = PasswordStrengthChecker(pw)
        strength, score, entropy, feedback = checker.analyze()
        lines.append(f"\nPassword: {'*' * len(pw)}")
        lines.append(f"  Strength : {strength} (score {score}/10, entropy {entropy} bits)")
        for tip in feedback:
            lines.append(f"  - {tip}")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Checked {len(passwords)} password(s). Report saved to '{report_path}'.")


# Main program

def main():
    print("=== DecodeLabs Password Strength Checker ===")
    print("Commands: type a password to check it, 'suggest' for a strong password,")
    print("'batch <filename>' to check a whole file, or 'exit' to quit.\n")

    while True:
        user_input = input("> ").strip()

        if user_input.lower() == "exit":
            print("Goodbye! Stay secure. 🔐")
            break

        elif user_input.lower() == "suggest":
            print(f"Suggested strong password: {suggest_strong_password()}")

        elif user_input.lower().startswith("batch "):
            filepath = user_input[6:].strip()
            try:
                batch_check(filepath)
            except FileNotFoundError:
                print(f"File not found: {filepath}")

        elif user_input == "":
            print("Please enter a password, or type 'exit' to quit.")

        else:
            display_result(user_input)


if __name__ == "__main__":
    main()

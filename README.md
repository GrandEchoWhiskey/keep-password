# Program Description

The given program is a password generator that creates secure passwords based on certain criteria. It utilizes various checks to ensure the generated passwords meet specific requirements. Here's an overview of the program's functionality and structure:

## Class: password
### Constructor
- The constructor `__init__` initializes the `password` class object.
- It takes a `charset` parameter, which is a set of characters used to generate passwords.
- The constructor initializes private attributes:
  - `__charset`: A sorted set of characters from the given charset parameter.
  - `__database`: A list to store passwords loaded from two password databases (`big1_pwds.db` and `big2_pwds.db`).
  - `__small`: A list to store passwords loaded from a small password database (`small_pwds.db`).

### Method: generate
- This method generates a password of a specified `length`.
- It uses the `randbelow` function from the `secrets` module to select random characters from the `__charset`.
- The method is a generator, yielding one character at a time.

### Property: charset
- This property allows access to the `__charset` attribute.

### Static Method: check_symbols
This method checks the presence of different symbol types in a given pwd (password) string.
It returns a float value indicating the percentage of symbol types present in the password.

### Static Method: check_length
This method checks the length of a given pwd string against specified minimum and maximum lengths (min_l and max_l).
It returns a float value indicating the percentage of how close the password length is to the allowed range.

### Static Method: check_repetition
This method checks for the repetition of characters in a given pwd string.
It returns a float value indicating the percentage of unique characters in the password.

### Method: check_database
This method checks if a given pwd string is present in the password databases loaded during initialization.
It returns a float value indicating the percentage of passwords in the databases that match the given password.

### Method: check_small
This method checks if the given pwd string contains any passwords from the small password database.
It calculates a score based on the presence of small passwords in the generated password.
It returns a float value indicating the score.

### Method: create_secure
This method generates a secure password by combining the functionalities of different checks.
It takes an optional length parameter (default: 8) to specify the length of the password.
It calculates a score based on the individual check results and multiplies them together.
It returns a tuple containing the score and the generated password.

### Method: print_best
This method generates multiple passwords and selects the best one based on the score.
It takes optional parameters: length (default: 16) to specify the length of the password and iters (default: 100) to specify the number of iterations.
It iteratively generates passwords and prints the current best password and its score.
Finally, it returns the best password as a tuple containing the score and the password.

### Function: charset
This function generates a character set based on the provided start and end ASCII values.
It takes optional parameters: start (default: 33) and end (default: 127) to specify the ASCII range.
It also takes an optional exc (default: ""\'(),.[]`{}|~") parameter to exclude specific characters.
It returns a sorted set of characters.

### Main Code
The main code block checks if the script is being run as

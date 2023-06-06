from secrets import randbelow

class password:

    def __init__(self, charset: set) -> None:
        self.__charset = sorted(set(charset))
        self.__database = list()
        self.__small = list()

        with open('big1_pwds.db', 'r') as f:
            for line in f:
                self.__database.append(line.strip())

        with open('big2_pwds.db', 'r') as f:
            for line in f:
                self.__database.append(line.strip())

        with open('small_pwds.db', 'r') as f:
            for line in f:
                self.__small.append(line.strip())

    def generate(self, length: int) -> str:
        for _ in range(length):
            yield self.__charset[randbelow(len(self.__charset))]

    @property
    def charset(self) -> list:
        return self.__charset
    
    @staticmethod
    def check_symbols(pwd: str) -> float:
        """Checks for symbols in the password."""
        __s = [0, 0, 0, 0]
        for __c in pwd:
            if ord(__c) in range(ord('0'), ord('9') + 1):
                __s[0] |= True
            elif ord(__c) in range(ord('a'), ord('z') + 1):
                __s[1] |= True
            elif ord(__c) in range(ord('A'), ord('Z') + 1):
                __s[2] |= True
            else:
                __s[3] |= True
        return (sum(__s) / len(__s)) * 100.0

    @staticmethod
    def check_length(pwd: str, min_l: int = 8, max_l: int = 20) -> float:
        """Checks the length of the password."""
        __pwd_l = len(pwd)
        if __pwd_l < min_l:
            return 0.0
        elif __pwd_l > max_l: 
            return 100.0
        else:
            return ((__pwd_l - min_l + 1) / (max_l - min_l)) * 100.0
        
    @staticmethod
    def check_repetition(pwd: str) -> float:
        """Checks for repetition of characters."""
        __s = {}
        for __c in pwd:
            if __c in __s:
                __s[__c] += 1
            else:
                __s[__c] = 1
        return (len(__s) / len(pwd)) * 100.0
    
    def check_database(self, pwd: str) -> float:
        """Does not contain any passwords below 8 characters."""
        if pwd in self.__database:
            return 0.0
        return 100.0
    
    def check_small(self, pwd: str) -> float:
        __score = 100.0
        for __small in self.__small:
            if __small in pwd:
                __score -= 8/len(pwd)
        return __score
    
    def create_secure(self, length: int = 8) -> str:
        pwd = ''.join(self.generate(length))
        x = 150.0
        x *= (self.check_symbols(pwd) / 100.0)
        x *= (self.check_length(pwd) / 100.0)
        x *= (self.check_repetition(pwd) / 100.0)
        x *= (self.check_database(pwd) / 100.0)
        x *= (self.check_small(pwd) / 100.0)
        return (x, pwd)
    
    def print_best(self, length: int = 16, iters: int = 100) -> str:
        if length <= 0: raise ValueError('Length must be greater than 0.')
        if iters <= 0: raise ValueError('Iterations must be greater than 0.')
        __b = (-1.0, '')
        for _ in range(iters):
            __new = self.create_secure(length)
            if __new[0] > __b[0]:
                __b = __new
            print(f'{__new[1]}: {min(__new[0], 100):.2f}%  ', end='\r', flush=True)
        print(f'{__b[1]}: {min(__b[0], 100):.2f}%  ')
        return __b
            
    
def charset(start = 33, end = 127, exc = "\"\\\'(),.[]`{}|~"):
    return sorted(set([chr(x+start) for x in range(end-start)]) - set(exc))

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print('Usage: python3 main.py <length> <iterations>')
        sys.exit(1)
    p = password(charset())
    p.print_best(int(sys.argv[1]), int(sys.argv[2]))

    

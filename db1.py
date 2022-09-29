from dataclasses import dataclass, asdict

class Database:
    def __init__(self):
        self.db = {}
    
    def create_table(self, table_name: str, expected_object) -> None:
        self.db[table_name] = list()
        
    def insert_into_table(self, table_name: str, value) -> None:
        self.db[table_name].append(asdict(value))
        
    def query(self, table_name: str, value_name, expected_value):
        final = [i for i in self.db[table_name] if i[value_name] == expected_value]
        '''for i in self.db[table_name]:
            if i[value_name] == expected_value:
                final.append(i)'''
        return final

@dataclass(frozen=True, order=True)
class Person:
    name: str
    job: str
    age: int

x = Database()
x.create_table('people', '__main__.Person')

james = Person('James', 'Cook', 22)
x.insert_into_table('people', james)
charles = Person('Charles', 'Shoemaker', 22)
x.insert_into_table('people', charles)

print(x.query('people', 'age', 22))

from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()
password = 'dupa12'
hashed = bcrypt.generate_password_hash(password).decode('utf-8')
print(hashed)

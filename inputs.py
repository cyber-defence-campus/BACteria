DEVICE_ID = 1234
PASSWORD = "password"


Device_Identifier = b'\x02' +DEVICE_ID.to_bytes(3,'big')
Password_char = (len(PASSWORD)+1).to_bytes(1,'little')+ b'\x00' + PASSWORD.encode()
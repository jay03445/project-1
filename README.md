This is a restful JWKS server that will generate public keys with identifiers called kids for the verification of JSON Web Tokens. For testing key rotation, JWTs will test for users' inputs for expired key tokens when the expired query parameter is defined. 
Files include: 
server.py
test_server.py
requirements.txt
Running the Server in PowerShell Terminal: 
python server.py
python -m pytest --cov=app --cov=tests
Running the Gradebot in a Second Powersheel Terminal:
.\gradebot.exe project-1 --run="python server.py"

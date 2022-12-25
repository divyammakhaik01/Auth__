from flask import Flask , request , jsonify , make_response ,render_template, session , redirect 
import jwt
from datetime import datetime , timedelta 
from functools import wraps
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt

# init app
app = Flask(__name__)



app.config['SECRET_KEY'] = "12345"

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'flask_app'
 
mysql = MySQL(app)
bcrypt = Bcrypt(app)


@app.route('/')
def hello_world():
    if not session.get('name'):
        return render_template('login.html')
    else:
        data =  session.get('name')
        return render_template('home.html' , name = data)
        # return jsonify({
        #     "status" : "OK" , 
        #     "message" :"User logged in successfully"
        # })


@app.route('/logout')
def logout():
    if  session.get('name'):
        session.pop('name')

    return redirect("http://127.0.0.1:5000/login")
    # return render_template('login.html')


# /login
@app.route('/login',methods=['POST' , 'GET'])
def login():
    if request.method == 'GET':
        # session["name"] = request.form.get("name")

        return render_template('login.html')
    else:
        email = request.form['email'] 
        password = request.form['password']

        if email and password : 
            # check
            cursor = mysql.connection.cursor()
            cursor.execute('''SELECT * FROM flask_app.User where email = %s  ''' , [email])
            result = cursor.fetchall()
            result_list = list(result)


            # if email || password not found 
            if len(result_list) == 0 : 
                return redirect("http://127.0.0.1:5000/register")
            else:
                pw_hash = result_list[0][4]
                
                hp = bcrypt.generate_password_hash(password)

                if(bcrypt.check_password_hash(pw_hash , bytes(request.form['password'], 'utf-8')) == True):
                    token = jwt.encode( {
                    'user': email,
                    'exp': str(datetime.utcnow() + timedelta(seconds=60))
                    },
                    app.config['SECRET_KEY']
                    )
                    name = result_list[0][1]
                    session["name"] = name

                    return redirect("http://127.0.0.1:5000/")

                else:
                    return redirect("http://127.0.0.1:5000/register")

                    # return jsonify({
                    #     "status" : "false" , 
                    #     "message" : "incorrect password !!" 
                    # })
        else:
            return redirect("http://127.0.0.1:5000/register")
            # return jsonify({
            #     "status" : "false" , 
            #     "message" : "email or password not found "
            # })


#  /register

@app.route('/register',methods=['POST' , 'GET'])
def register():

    if request.method == 'GET':
        return render_template('register.html')
    else:
        name = request.form['name']
        email = request.form['email'] 
        password = request.form['password']
        mobile = request.form['mobile']

        if email and password and mobile and name: 
            cursor = mysql.connection.cursor()
            cursor.execute('''SELECT * FROM flask_app.User where email = %s ''' , [email])
            result = cursor.fetchall()
            result_list = list(result)

            # if email already exist in database
            if len(result_list) == 1 : 
                return jsonify({
                    "status" : "ok" , 
                    "message" : "email already exist"
                })
                # return redirect("http://127.0.0.1:5000/register")
            else:
                # insert into database
                cursor = mysql.connection.cursor()
                hashedPassword = bcrypt.generate_password_hash(password)
                cursor.execute('''INSERT INTO flask_app.User (name ,email ,mobile_number , password ) VALUES  (%s ,%s, %s, %s)  ''' , [name , email , mobile , hashedPassword])
                mysql.connection.commit()

                return redirect("http://127.0.0.1:5000/login")
                # return jsonify({
                #     "status" : "OK" ,
                #     "message" : "data inserted successfully ", 
                # })
        else:
            return jsonify({
                "status" : "false" , 
                "message" : "all fields are required "
            })

        
        


if __name__ == '__main__':
    app.run(debug=True)
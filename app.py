from flask import Flask, render_template, request, redirect, url_for, flash,session
import pymongo
from pymongo import MongoClient
import json
from flask_mail import Mail,Message
from werkzeug.security import generate_password_hash , check_password_hash
from random import randint
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import os
import razorpay

app = Flask(__name__)
mail = Mail(app)
s = URLSafeTimedSerializer('Thisisasecret!') 
app.secret_key = os.urandom(24)

app.config["MAIL_SERVER"]='smtp.gmail.com'
app.config["MAIL_PORT"]=587
app.config["MAIL_USERNAME"]='verifyidentity18@gmail.com'
app.config['MAIL_PASSWORD']='qwerty@12345'                    
app.config['MAIL_USE_TLS']=True
app.config['MAIL_USE_SSL']=False
mail=Mail(app)
otp=randint(000000,999999)


##-------------------------------------------- Connecting to database-----------------##

try:
	cluster = MongoClient("mongodb+srv://dinesh:123dinesh@cluster0.vkomn.mongodb.net/userdb?retryWrites=true&w=majority")
	db = cluster["userdb"]
	collection = db["userinfo"]
	print("connected")
except :
	print("Error Connecting to database")	

##----------------------------------------------app routes----------------------------##	

@app.route('/')
def index():
	if ("user_id") in session:
		user = session["user_id"]
		return redirect(url_for('loggedinpage',user = user))
	else:
		return render_template("page1signin.html")

#---------------------------#

@app.route('/logout')
def logout():
	session.pop("user_id",None)
	return redirect(url_for('mainpagewosignin'))
@app.route('/mainpagewosignin')
def mainpagewosignin():
	return render_template("page1signin.html")	

#---------------------------#
@app.route('/signup')
def signup():
	return render_template("signup.html")
@app.route('/validateSignup', methods = ["POST","GET"])
def validateSignup():
	
	email = request.form["email"]
	username = request.form["username"]
	password = request.form["password"]
	r = db.userinfo.find( { "email": email } )
	find_email = "not_found_email"
	for i in r:
		find_email = i
	if find_email == "not_found_email":
		q = db.userinfo.find( { "username": username } )
		find_username = "not_found_username"
		for x in q:
			find_username = x
		if find_username == "not_found_username":
			
			token = s.dumps(email, salt='email-confirm')
			hashed_password = generate_password_hash(password , method = 'sha256')
			db.userinfo.insert_one({"email":email,"username":username,"password":hashed_password,"token":token , "verified" : 0})
			msg = Message('Confirm Email', sender='verifyidentity18@gmail.com', recipients=[email])
			link = url_for('confirm_email', token=token, _external=True)
			msg.body = 'Your verification  link is {}'.format(link)
			mail.send(msg)
			msg1 = "Register successfully , click the verification link send to the {}".format(email)
			return render_template("signup.html",infos = msg1)
			
		else: 
			msg2 ="username already exist"
			return render_template("signup.html",infoss = msg2)
	else:
		msg3 =  "email already exist"
		return render_template("signup.html",infosss = msg3)

#---------------------------#

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
    	print(token)
    	emails = s.loads(token, salt='email-confirm', max_age = 3600)
    	t = db.userinfo.find( { "token":token } )
    	tk = "tk"
    	for y in t :
    		print(y)
    		tk = y	
    	if tk == "tk":
    			return "not  are not verfied yet.. :("
    	else:
    		db.userinfo.update({ "token": token },{ "$set":{"verified":1}})
    		msg4= "Now u are verified, Login now"
    		return render_template("login.html", message = msg4)
    except:
    	return '<h1>The token is expired!.. :(</h1>'
    return 'ERROR :('

#---------------------------#

@app.route('/loginpage')
def login_page():
	if ("user_id") in session:
		user = session["user_id"]
		return redirect(url_for('loggedinpage',user = user))
	else:
		return render_template("login.html")

#---------------------------#

@app.route ('/login',methods = ["POST","GET"])
def login():
	if ("user_id") in session:
		user = session["user_id"]
		return redirect(url_for('loggedinpage',user = user))
	else:
		user =  request.form["username"]
		password  = request.form ["password"]
		a = db.userinfo.find( { "$or": [ { "email": user }, { "username": user } ] } )
		
		find = "found"
		for i in a:
			if i is None:
				msg1 = "User doesn't exist"
				break
			else:
				print("################ : : : - ",i)
				find =i
				hashed_password = i["password"]
				usn = i["username"]
				print("+++++++++++++++++",usn)	
				print("****",hashed_password,"****")
				result = check_password_hash(hashed_password,password)
				print(result)
		if find == "found":
			msg1 = "User doesn't exist"
			return render_template("login.html", info = msg1 )
			return "user not exist"
		else:
			if ((user == i["username"] or user == i["email"]) and (result == True)):
				v = db.userinfo.find( {"$or":[{ "email": user } , { "username": user }]}, { "verified": 1  } )
				for s in v:
					ver = s["verified"]

				if ver == 0 :
					msg2 = "Not verified yet, first verify then login"
					return render_template("login.html", info = msg2)
				else:
					session["loggedin"] = True
					session["user_id"] = usn
					print("matched")
					return redirect(url_for('loggedinpage',user = usn))
			else:
				print("not matched")
				msg3 = "wrong password"
				return render_template("login.html" , info =  msg3)	

#---------------------------#

@app.route('/loggedinpage/<user>')
def loggedinpage(user):
	if ("user_id") in session:
		return render_template("page1.html",user = user)			
	else:
		return redirect(url_for('login_page'))	

#--------------------------#

@app.route('/enteremail')
def enteremail():
	return render_template("enteremail.html")


#--------------------------#

@app.route ('/verify',methods = ["POST","GET"])
def enter_email():
	try:
		email = request.form["email"]
		z = db.userinfo.find( { "email": email }, { "token"  } )
		for i in z :
			token  = i["token"]
		msg = Message('Confirm Email', sender='verifyidentity18@gmail.com', recipients=[email])
		link = url_for('confirm_email', token=token, _external=True)
		confirm = link
		msg.body = "click the verification link send to the {}".format(link) 
		mail.send(msg)
		msg1 = "click the verification link send to the {}".format(email) 
		return render_template("enteremail.html",infos = msg1)
	except:
		msg2 = "user doesn't exist"
		return render_template("enteremail.html",info = msg2)	

#---------------------------#

@app.route('/fg',methods = ["POST" , "GET"])
def fg():
	return render_template("send_otp.html")
	
#-----------------------------#

@app.route('/forgot_password',methods = ["POST" , "GET"])
def forgot_password():
	email = request.form["email"]
	msg = "user doesn't exist"
	q = db.userinfo.find( { "email": email }, { "email"  })
	print(q)
	
	for i in q:
		if i is None:
			break
		else:
			msg=Message(subject='OTP',sender='verifyidentity18@gmail.com',recipients=[email])
			msg.body= str(otp)
			mail.send(msg)
		#	return  render_template("send_otp.html",email  = email)
			return redirect(url_for('check',email = email))
	return render_template("send_otp.html",msg = msg)		

#-----------------------------#

@app.route('/check/<email>')	
def check(email):
	print(email)
	return render_template('verify_otp.html',email = email)

#-----------------------------#

@app.route('/verifyotp/<email>',methods = ["POST","GET"])
def verify_otp(email):
	email_to_change = email 
	print(email_to_change)
	user_otp  = request.form["otp"]
	if otp == int(user_otp):
		password  = request.form["password"]
		again_password = request.form["again_password"]
		if password == again_password:
			hashed_password = generate_password_hash(password , method = 'sha256')
			db.userinfo.update_one({ "email": email }, {"$set": {"password": hashed_password }})
			msg = "password reset successful"
			return render_template("login.html",infos = msg)
		else:
			msg =  "password does not match"
			return render_template("send_otp.html",info = msg)
		#return redirect(url_for('reset_password',email = email))
	else:
		msg1 =  "wrong otp"
		return render_template("send_otp.html", infow = msg1)
	return render_template("verify_otp.html")	



#-----------------------------#

@app.route('/home')	
def homepage():
	user = session["user_id"]
	return render_template("page1.html",user = user)
@app.route('/place')	
def place():
	if ("user_id") in session:
		user = session["user_id"]
		return render_template("page2.html",user= user)
	else:
		return render_template("page2.1.html")	
		
@app.route('/food')	
def food():
	if ("user_id") in session:
		user = session["user_id"]
		return render_template("page3.html",user= user)
	else:
		return render_template("page3.1.html")	
@app.route('/trekking')	
def trekking():
	if ("user_id") in session:
		user = session["user_id"]
		return render_template("page4.html",user= user)
	else:
		return render_template("page4.1.html")	
@app.route('/contact')	
def contact():
	if ("user_id") in session:
		user = session["user_id"]
		return render_template("page5.html",user= user)
	else:
		return redirect(url_for('login_page'))	
@app.route('/booking')	
def booking():
	if ("user_id") in session:
		user = session["user_id"]
		return render_template("page6.html",user= user)
	else:
		return redirect(url_for('login_page'))	
@app.route('/package')	
def package():
	if ("user_id") in session:
		user = session["user_id"]
		return render_template("page7.html",user= user)
	else:
		return redirect(url_for('login_page'))	

@app.route ('/savebooking',methods = ["POST","GET"])
def savebooking():
	if ("user_id") in session:
		user = session["user_id"]
		name = request.form["visitor_name"]	
		email = request.form["visitor_email"]
		phone = request.form["visitor_phone"]
		adults = request.form["total_adults"]
		children = request.form["total_children"]
		checkin = request.form["checkin"]
		checkout = request.form["checkout"]
		message = request.form["visitor_message"]

		try:
			db.userinfo.update_one(
   { "username": user},
   { "$set":
      {
        "bookingArray": [{"name":name , "email":email , "phone":phone , "adults":adults,
													"children" : children , "checkin" : checkin ,"checkout": checkout,
													 "message":message}]}})


			z =db.userinfo.find( { "username": { "$in": [ user ] } })
			for i in z:
				print(checkout ,checkin)
				em=  (i["email"])
				msg=Message(subject='Confirmation of booking',sender='verifyidentity18@gmail.com',recipients=[em])
				msg.body= "Your Booking is confirmed for Dharamshala from {} to {} .".format(checkin , checkout)
				mail.send(msg)
			return redirect(url_for('confirmation'))
		except: return "Error while booking :("
#"Your Booking is confirmed for Dharamshala"
@app.route('/confirmation')
def confirmation():
	if ("user_id") in session:
		user = session["user_id"]
		return render_template("confirmation.html",user = user)
	else:
		return redirect(url_for('login_page'))

##-------------------------------------------------------------------------------------------------##
@app.route('/payment1/<user>',methods = ["POST","GET"])
def payment1(user):
	
	client = razorpay.Client(auth = ("rzp_test_jt1NMWvEInSGIt","wkuS4nu6Kta8ZjoJZN8YNUkZ"))
	payment = client.order.create({ 'amount':110000,'currency':'INR','payment_capture':'1'})
	return render_template('pay.html',payment = payment,user = user,description= "Kareri Lake ,Trek")


@app.route('/payment2/<user>',methods = ["POST","GET"])
def payment2(user):
	
	client = razorpay.Client(auth = ("rzp_test_jt1NMWvEInSGIt","wkuS4nu6Kta8ZjoJZN8YNUkZ"))
	payment = client.order.create({ 'amount':100000,'currency':'INR','payment_capture':'1'})
	return render_template('pay.html',payment = payment,user = user,description= "Triund Trek, Mcleodganj")


@app.route('/payment3/<user>',methods = ["POST","GET"])
def payment3(user):
	
	client = razorpay.Client(auth = ("rzp_test_jt1NMWvEInSGIt","wkuS4nu6Kta8ZjoJZN8YNUkZ"))
	payment = client.order.create({ 'amount':200000,'currency':'INR','payment_capture':'1'})
	return render_template('pay.html',payment = payment,user = user,description= "Strawberry Village")


@app.route('/payment4/<user>',methods = ["POST","GET"])
def payment4(user):
	
	client = razorpay.Client(auth = ("rzp_test_jt1NMWvEInSGIt","wkuS4nu6Kta8ZjoJZN8YNUkZ"))
	payment = client.order.create({ 'amount':300000,'currency':'INR','payment_capture':'1'})
	return render_template('pay.html',payment = payment,user = user,description= "Waterfall Trek & Paragliging, Bir")

@app.route('/payment5/<user>',methods = ["POST","GET"])
def payment5(user):
	
	client = razorpay.Client(auth = ("rzp_test_jt1NMWvEInSGIt","wkuS4nu6Kta8ZjoJZN8YNUkZ"))
	payment = client.order.create({ 'amount':200000,'currency':'INR','payment_capture':'1'})
	return render_template('pay.html',payment = payment,user = user,description= "Mcleodganj & Bhagsu")


@app.route('/payment6/<user>',methods = ["POST","GET"])
def payment6(user):

	client = razorpay.Client(auth = ("rzp_test_jt1NMWvEInSGIt","wkuS4nu6Kta8ZjoJZN8YNUkZ"))
	payment = client.order.create({ 'amount':220000,'currency':'INR','payment_capture':'1'})
	return render_template('pay.html',payment = payment,user = user,description= "Riverside Camping & BBQ")


@app.route('/payment7/<user>',methods = ["POST","GET"])
def payment7(user):
	
	client = razorpay.Client(auth = ("rzp_test_jt1NMWvEInSGIt","wkuS4nu6Kta8ZjoJZN8YNUkZ"))
	payment = client.order.create({ 'amount':150000,'currency':'INR','payment_capture':'1'})
	return render_template('pay.html',payment = payment,user = user,description= "Prashar Lake Trek")		
##----------------------------------------------------------------------------------------------------#
 
@app.route('/success/<user>/<description>')
def success(user,description):
	#return render_template("success.html")
	print(user)
	print(description)
	z =db.userinfo.find( { "username": { "$in": [ user ] } })
	for i in z:
		em = (i['email'])
		print(em)
		msg=Message(subject='Payment Successful',sender='verifyidentity18@gmail.com',recipients=[em])
		msg.body= "Your Payment for {} is successful.".format(description)
		mail.send(msg)
		return render_template("success.html")
	else:
		return "error"	
##-------------------------------------------app run ------------------------------##
		

if __name__ == '__main__':
	app.run(port = 80 , debug = True)

import os, random, string,requests
from flask import Flask, redirect, render_template, request,make_response,abort,request,flash,session,url_for,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
import json

app = Flask(__name__)
csrfobj = CSRFProtect(app)
app.config.from_pyfile("config.py")
app.config["DEBUG"] = True

SQLALCHEMY_DATABASE_URI= 'mysql+mysqlconnector://root@localhost/isoye'
SQLALCHEMY_TRACK_MODIFICATIONS=True
    

db = SQLAlchemy(app)




import os
SECRET_KEY= os.urandom(32)

import datetime,mysql.connector
class Room(db.Model):
    __tablename__='Room'
    room_id= db.Column(db.Integer(), primary_key=True, autoincrement=True)
    room_type = db.Column(db.String(45), nullable = False)
    room_status= db.Column(db.String(100), nullable = False)
    room_number = db.Column(db.Integer())
    room_price = db.Column(db.Integer())


class Customer(db.Model):
    __tablename__='Customer'
    customer_id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    customer_fname = db.Column(db.String(45), nullable = False)
    customer_lname = db.Column(db.String(45), nullable = False)
    customer_email = db.Column(db.String(75), nullable = False)
    customer_phone = db.Column(db.String(35), nullable = False)
    customer_pwd = db.Column(db.String(35), nullable = False)
    customer_signupdate = db.Column(db.DateTime(), default=datetime.datetime.utcnow)
  
class Gallery(db.Model):
    __tablename__='Gallery'
    gallery_id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    description = db.Column(db.String(45), nullable= False )
    pics = db.Column(db.String(45), nullable= False )

class Booking(db.Model):
    __tablename__='Booking'
    Booking_id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    Customer_id = db.Column(db.Integer(),db.ForeignKey('Customer.customer_id'),nullable = False)
    room_id = db.Column(db.Integer(),db.ForeignKey('Room.room_id'),nullable = False)
    payment_id = db.Column(db.Integer(),db.ForeignKey('Payment.payment_id'),nullable = False)
    booking_date = db.Column(db.DateTime(), default=datetime.datetime.utcnow)
    arrival = db.Column(db.String(45), nullable = False)
    departure = db.Column(db.String(45), nullable = False)

class Payment(db.Model):
    __tablename__='Payment'
    payment_id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    payment_status = db.Column(db.String(45), nullable = False)
    payment_date = db.Column(db.DateTime(), default=datetime.datetime.utcnow)
    customer_id = db.Column(db.Integer(), db.ForeignKey('Customer.customer_id') ,nullable=False)
    payment_amt = db.Column(db.BigInteger(), nullable=False)
    room_id = db.Column(db.Integer(), db.ForeignKey('Room.room_id') ,nullable=False)
    payment_ref= db.Column(db.String(45), nullable=False)
    




class Checkin(db.Model):
    __tablename__='Checkin'
    checkin_id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    customer_id = db.Column(db.Integer(), db.ForeignKey('Customer.customer_id') ,nullable=False)
    payment_id = db.Column(db.Integer(),db.ForeignKey('Payment.payment_id'),nullable = False)
    room_id = db.Column(db.Integer(), db.ForeignKey('Room.room_id') ,nullable=False)
    duration=  db.Column(db.String(225), nullable = False)
    checkin_date = db.Column(db.DateTime(), default=datetime.datetime.utcnow)
    

class Checkout(db.Model):
    __tablename__='Checkout'
    checkout_id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    customer_id = db.Column(db.Integer(), db.ForeignKey('Customer.customer_id') ,nullable=False)
    payment_id = db.Column(db.Integer(),db.ForeignKey('Payment.payment_id'),nullable = False)
    room_id = db.Column(db.Integer(), db.ForeignKey('Room.room_id') ,nullable=False)
    duration=  db.Column(db.String(225), nullable = False)
    checkout_date = db.Column(db.DateTime(), default=datetime.datetime.utcnow)


class Room_Pic(db.Model):
    __tablename__='Room_Pic'
    pic_id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    room_pic = db.Column(db.String(225), nullable = False)
    room_id = db.Column(db.Integer(), db.ForeignKey('Room.room_id') ,nullable = False)


class Room_Gallery(db.Model):
    __tablename__='Room_Gallery'
    pic_id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    room_pics = db.Column(db.String(225), nullable = False)
    room_id = db.Column(db.Integer(), db.ForeignKey('Room.room_id') ,nullable = False)


















from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,BooleanField,SubmitField,TextAreaField,IntegerField,FileField,SelectField
from wtforms.fields.simple import FileField
from wtforms.validators import DataRequired,Email

class login(FlaskForm):
    email = StringField('Email', validators=[Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

class regi(FlaskForm):
    fname = StringField("First Name:", validators=[DataRequired()])
    lname = StringField("Last Name:", validators=[DataRequired()])
    email = StringField("Email:", validators=[Email()])
    phone = StringField("Phone:",  validators=[DataRequired()])
    password = PasswordField("Password:", validators=[DataRequired()])
    password2 = PasswordField("Confirm Password:", validators=[DataRequired()])
    submit = SubmitField("Submit")

class adminlog(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired('Password Required')])
    submit = SubmitField('Submit')

class adminadd(FlaskForm):
    room_type = StringField("Room Type", validators=[DataRequired()])
    room_number = StringField("Room Type", validators=[DataRequired()])
    room_price = StringField("Room Type", validators=[DataRequired()])
    pica = FileField("Choose a File:", validators=[DataRequired()])
    picb = FileField("Choose a File:", validators=[DataRequired()])
    picc = FileField("Choose a File:", validators=[DataRequired()])
    picd = FileField("Choose a File:", validators=[DataRequired()])
    submit = SubmitField('Submit')

class admingall(FlaskForm):
    description = StringField("Room Type", validators=[DataRequired()])
    pica = FileField("Choose a File:", validators=[DataRequired()])
    submit = SubmitField('Submit')








@app.route('/')
def mainpage():
    return render_template('abuja.html')





@app.route('/rooms')
def rooms():
    r = db.session.query(Room,Room_Gallery).filter(Room.room_id == Room_Gallery.room_id).union_all()
    return render_template('rooms.html',r=r)



@app.route('/gallery')
def gallery():
    g = db.session.query(Gallery).all()
    return render_template('gallery.html',g=g)


@app.route('/about')
def about():
    return render_template('about.html')





@app.route('/contact')
def contact():
    return render_template('about.html')



@app.route('/services')
def services():
    return render_template('about.html')


@app.route('/book',methods=['POST','GET'])
def book():
    loggedin = session.get('user')
    if loggedin !=None:
        room = request.form.get('roomno')
        display = db.session.query(Room).filter(Room.room_id == room).first()
        pic = db.session.query(Room_Pic).filter(Room_Pic.room_id == room).all()
        return render_template("book.html",display=display,pic=pic)
    else:
        return redirect('/login')





def generate_ref():
    contents = random.sample(string.digits,10)
    r = ''.join(contents)
    return r

@app.route('/payment',methods=['POST','GET'])
def payment():
    from datetime import date
    room = request.form.get('roomno')
    arr = request.form.get('arrival')
    dep = request.form.get('departure')
    rm = db.session.query(Room).filter(Room.room_id == room).first()
    rp = rm.room_price
    rid = rm.room_id
    custid = session.get('user')
    amtkobo = float(rp)*100
    refno = generate_ref()
    session['ref']=refno
    
    pay = Payment(customer_id=custid,payment_amt=rp,payment_status='pending',payment_ref=refno,room_id=rid)
    db.session.add(pay)
    db.session.commit()
    pid = pay.payment_id
    book = Booking(Customer_id=custid,room_id=rid,payment_id=pid,arrival=arr,departure=dep)
    db.session.add(book)
    db.session.commit()
    deets = db.session.query(Payment).filter(Payment.payment_ref==refno).first()
    return render_template("payment.html", deets=deets,rid=rid)



@app.route('/admingalle', methods=['POST', 'GET'])
def admingalle():
    admin = session.get('admin')
    if admin !=None:
        add = admingall()
        return render_template('addgallery.html', add=add)
    else:
        return redirect('/adminlogin')



@app.route('/subadgalle', methods=['POST', 'GET'])
def subadgalle():
    admin = session.get('admin')
    if admin !=None:
        desc = request.form.get('description')
        pic = request.files.get('pica')
        i_paths = f"static/image/gallery"
        if pic !=None:
            pama = pic.save(f"{i_paths}/{desc}A.jpg")
            pd = Gallery(pics=f"static/image/gallery/{desc}A.jpg", description=desc)
            db.session.add(pd)
            db.session.commit()
            flash('success')
            return redirect('/admingalle')
    else:
        return redirect('/adminlogin')
    


@app.route('/buy', methods=['POST','GET'])
def buy():
    loggedin = session.get('user')
    if loggedin != None:
        room = request.form.get('roomno')
        r = db.session.query(Room).filter(Room.room_id == room).first()
        c = db.session.query(Customer).filter(Customer.customer_id == loggedin).first()
        g = r.room_id
        session['raid']=g
        cmail = c.customer_email
        ramt = r.room_price
        amtkobo = float(ramt)*100
        ref = session['ref']

        headers = {"Content-Type":"application/json","Authorization":"Bearer sk_test_43e19b3e6ac8aac056ae0ce60996bf35ccf07838","Cache-Control":"no-cache"}
        data = {
            "reference":ref,"amount":amtkobo,
            "email":cmail
        }
        rsp = json.dumps(data)
        Response = requests.post("https://api.paystack.co/transaction/initialize",headers=headers,data=rsp)
        response_json=Response.json()
        if response_json['status']==True:
            auth_url = response_json['data']['authorization_url']
            return redirect(auth_url)
        else:
            flash('Try again')
            return redirect('/rooms')




@app.route('/payverify')
def payverify():
    trxref= request.args.get('trxref')
    headers = {"Content-Type":"application/json",
        "Authorization": "Bearer sk_test_43e19b3e6ac8aac056ae0ce60996bf35ccf07838",
        "Cache-Control":"no-cache"
        }
    #connect to paystack and confirn status of transaction
    response = requests.get(f'https://api.paystack.co/transaction/verify/{trxref}', headers=headers)
    rsp = response.json()
    rad = session.get('raid')
    #update database 
    db.session.execute(f"UPDATE payment SET payment_status='Paid' WHERE payment_ref='{trxref}'")
    db.session.commit()

    db.session.execute(f"UPDATE room SET room_status='booked' WHERE room_id='{rad}'")
    db.session.commit()

    #insert into booking

    return redirect('/paid')
    

          


@app.route('/paid', methods=['POST', 'GET'])
def paid():
    ref = session['ref']
    deets = db.session.query(Payment).filter(Payment.payment_ref==ref).first()
    paying_customer = session['user']     
    return render_template("userorder.html",deets=deets)    



@app.route('/login',methods=['POST','GET'])
def log():
    lg = login()
    if request.method=='GET':
        return render_template('login.html',lg=lg)
    else:
        if lg.validate_on_submit():
            mymail = request.form.get('email')
            mypwd =  request.form.get('password')
            check =Customer.query.filter(Customer.customer_email==mymail).first()
            if check !=None:
                stored_hash = check.customer_pwd
                #pwdd= check_password_hash(stored_hash,mypwd)
                if mypwd==stored_hash:
                    session['user']=check.customer_id
                    session['userfname']=check.customer_fname
                    session['userlname']=check.customer_lname
                    session['useremail']=check.customer_email
                    #return render_template("userlogin.html",lg=lg)
                    return redirect('/rooms') 
                else:
                    flash('Invalid details')
                    return redirect('/login')
            else:
                flash("Incorrect Details")
                return redirect('/login')
        else:
            return render_template("login.html",lg=lg)




@app.route('/signout')
def signout():
    if session.get('user')!=None:
        session.pop('user')
        session.pop('userfname')
        session.pop('useremail')
        return redirect('/')
    else:
        return render_template('abuja.html')



@app.route('/register',methods=['POST','GET'])
def reg():
    loggedin=session.get('user')
    reg = regi()
    #reg = register()
    if request.method=='GET':
        return render_template('register.html',reg=reg)
    else:
        fname= request.form.get('fname')
        lname= request.form.get('lname')
        mail = request.form.get('email')
        cell = request.form.get('phone')
        pwd = request.form.get('password')
        pwd2 = request.form.get('password2')
        if pwd == pwd2:
            #coded=  generate_password_hash(pwd, method='pbkdf2:sha256', salt_length=8)
            cust = Customer(customer_fname=fname,customer_lname=lname,customer_email=mail,customer_phone=cell,customer_pwd=pwd)
            db.session.add(cust)
            db.session.commit()
            session['user'] = cust.customer_fname
            return redirect('/login')
        else:
            flash ('Sorry your passwords do not match')
            return redirect('/register')





@app.route('/adminlogin',methods=['POST','GET'])
def adminlogin():
    ad = adminlog()
    if request.method=='GET':
        return render_template('adminlog.html',ad=ad)
    else:
        auth1 = 'tejadmin'
        auth2 = '55531'
        mail = ad.email.data
        pwd = ad.password.data
        if mail==auth1 and pwd ==auth2:
            session ['admin']=mail
            return redirect('/adminhome')
        else:
            return redirect('/adminlogin')



@app.route('/adminhome')
def adminhome():
    law = session.get('admin')
    if law ==None:
        ad = adminlog()
        return render_template('adminlog.html',ad=ad)
    else:
        return render_template('adminhome.html')
       




 
@app.route('/add')
def add():
    law = session.get('admin')
    if law ==None:
        ad = adminlog()
        return render_template('adminlog.html',ad=ad)
    else:
        add = adminadd()
        return render_template('adminadd.html',add=add)


@app.route('/admina',methods=['POST','GET'])
def admina():
    law = session.get('admin')
    from PIL import Image
    import os
    if law !=None:
        roomno = request.form.get('room_number')
        roomtype = request.form.get('room_type')
        roomprice = request.form.get('room_price')
        picA = request.files.get('pica')
        picB = request.files.get('picb')
        picC = request.files.get('picc')
        picD = request.files.get('picd')
        i_paths = f"static/image/rooms"
        if picA and picB and picC and picD !=None:
            pama = picA.save(f"{i_paths}/{roomno}A.jpg")
            pamb = picB.save(f"{i_paths}/{roomno}B.jpg")
            pamc = picC.save(f"{i_paths}/{roomno}C.jpg")
            pamd = picD.save(f"{i_paths}/{roomno}D.jpg")
            r = Room(room_type=roomtype,room_price=roomprice,room_number=roomno,room_status='available')
            db.session.add(r)
            db.session.commit()
            pr = r.room_number 
            p = Room_Gallery(room_pics=f"static/image/rooms/{roomno}A.jpg", room_id=pr)
            pa = Room_Pic(room_pic=f"static/image/rooms/{roomno}A.jpg", room_id=pr)
            pb = Room_Pic(room_pic=f"static/image/rooms/{roomno}B.jpg", room_id=pr)
            pc = Room_Pic(room_pic=f"static/image/rooms/{roomno}C.jpg", room_id=pr)
            pd = Room_Pic(room_pic=f"static/image/rooms/{roomno}D.jpg", room_id=pr)
            db.session.add(p)
            db.session.add(pa)
            db.session.add(pb)
            db.session.add(pc)
            db.session.add(pd)
            db.session.commit()
            flash ('success')
            return redirect('/adminhome')
    else:
        ad = adminlog()
        return render_template('adminlog.html',ad=ad)





















if __name__=='__main__':
    app.config['DEBUG']=True
    app.config['PORT'] = 8088
    app.config['SECRET_KEY']=SECRET_KEY
    app.run()


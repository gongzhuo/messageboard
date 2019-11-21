import os
import json
from datetime import datetime, date
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, ValidationError, Length, Email, Regexp, EqualTo
from flask import Flask, render_template, session, redirect, url_for, make_response, flash, jsonify, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_moment import Moment
from captchatool import CaptchaTool
from verificationcodetool import VerificationCodeTool
import redis

pool = redis.ConnectionPool(host='localhost', port=6379, decode_responses=True)
r = redis.Redis(connection_pool=pool)
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = "message board"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:gongzhuo@localhost:3306/gh_messageboard?charset=utf8mb4'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)
moment = Moment(app)
bootstrap = Bootstrap(app)
migrate = Migrate(app, db)


class LoginForm(FlaskForm):
    mobile = StringField('mobile', validators=[DataRequired()])
    captcha = PasswordField('captcha', validators=[DataRequired()])
    verification_code = PasswordField('verification_code', validators=[DataRequired()])
    submit = SubmitField(u'登录')


class MsgForm(FlaskForm):
    message = StringField('message', validators=[DataRequired()])
    submit = SubmitField(u'提交')


class UpdateMsgForm(FlaskForm):
    message = StringField('message', validators=[DataRequired()])
    submit = SubmitField(u'修改留言')


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)


class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(64))
    content = db.Column(db.Text)
    time = db.Column(db.TIMESTAMP, index=True, default=datetime.now)

    @staticmethod
    def to_json(msg):
        return {
            'id': msg.id,
            'author': msg.author,
            'content': msg.content,
            'time': json.dumps(msg.time, cls=DateEncoder)
        }

    @staticmethod
    def from_json(json_post):
        content = json_post.get('content')
        if content is None or content == '':
            raise ValidationError('post does not have a body')
        return Message(content=content)


def isLogin():
    login_status = session['csrf_token'] + '_login_status'
    if r.get(login_status) == 'true':
        return True
    else:
        return False


class DateEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime("%Y-%m-%d")
        else:
            return json.JSONEncoder.default(self, obj)


@app.route('/message_submit', methods=["POST"])
def message_submit():
    form = MsgForm()
    if form.validate_on_submit():
        user_key = session['csrf_token'] + '_user_key'
        user = r.get(user_key)
        print("user_key = " + user_key + ", value = " + r.get(user_key))
        if form.message.data is None:
            flash("输入内容为空")
        else:
            r_id = r.incr("msg_cnt")
            post = Message(content=form.message.data,
                           author=user,
                           id=r_id)
            db.session.add(post)
            db.session.commit()
            return redirect(url_for('message_query'))


@app.route('/message_query', methods=["GET"])
def message_query():
    form = MsgForm()
    if isLogin():
        msgs = Message.query.order_by(Message.time.desc())
        user_key = session['csrf_token'] + '_user_key'
        user = r.get(user_key)
        return render_template('pages/messages.html', form=form, name=user, messages=msgs)
    else:
        return redirect(url_for('login'))


@app.route('/messages_delete/<int:msg_id>', methods=['DELETE'])
def messages_delete(msg_id):
    print(msg_id)
    user_key = session['csrf_token'] + '_user_key'
    print("user_key = " + user_key + ", value = " + r.get(user_key))
    msg = Message.query.get(msg_id)
    db.session.delete(msg)
    db.session.commit()
    msgr = json.dumps(msg, default=msg.to_json)
    print("will delete : " + msgr)
    return msgr


@app.route('/messages_update/<int:msg_id>', methods=['POST'])
def messages_update(msg_id):
    form = UpdateMsgForm()
    if form.validate_on_submit():
        print(msg_id)
        msg = Message.query.get(msg_id)
        msg.content = form.message.data
        msg.time = datetime.now()
        db.session.commit()
    return redirect(url_for('message_query'))


@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()
    if form.validate_on_submit():
        session['name'] = form.mobile
        return redirect(url_for('pages/messages'))
    return render_template('pages/login.html', form=form, name=session.get('name'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print("用户已提交表单")
        user = User.query.filter_by(username=form.mobile.data).first()
        if user is None:
            user = User(username=form.mobile.data)
            db.session.add(user)
            db.session.commit()
            session['known'] = False
        else:
            session['known'] = True
        session['name'] = form.mobile.data
        # session.pop('user_name')
        # print(session)
        print(form.captcha.data)
        print(form.verification_code.data)
        # flash('您的短信验证码为 ：' + form.verification_code.data)
        cap_key = session['csrf_token'] + '_cap_key'
        code = r.get(cap_key)
        print(code)
        ver_key = session['csrf_token'] + '_ver_key'
        v_code = r.get(ver_key)
        print(v_code)
        if code != form.captcha.data or v_code != form.verification_code.data:
            print("验证码输入错误，请重新登录！")
            return render_template('pages/login.html', form=form)
        else:
            print("用户已通过验证")
            user_key = session['csrf_token'] + '_user_key'
            login_status = session['csrf_token'] + '_login_status'
            r.set(user_key, form.mobile.data)
            r.set(login_status, "true", ex=60*30)
            return redirect(url_for('message_query'))
    return render_template('pages/login.html', form=form)


@app.route('/logout')
def logout():
    login_status = session['csrf_token'] + '_login_status'
    r.set(login_status, "False")
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/get_captcha', methods=["GET"])
def get_captcha():
    """
    获取图形验证码
    :return:
    """
    new_captcha = CaptchaTool()
    # 获取图形验证码
    img, code = new_captcha.get_verify_code()
    # 存入session
    resp = make_response(img.getvalue())
    resp.headers['Content-Type'] = 'image/png'
    cap_key = session['csrf_token'] + '_cap_key'
    r.set(cap_key, code)
    print("set redis key = " + cap_key + ", value = " + code)
    return resp


@app.route('/get_verification_code', methods=["GET", "POST"])
def get_verification_code():
    """
    获取短信验证码
    :return:
    """
    new_verification_code = VerificationCodeTool()
    verification_code = new_verification_code.get_code()
    # 存入session
    ver_key = session['csrf_token'] + '_ver_key'
    r.set(ver_key, verification_code)
    print("set redis key = " + ver_key + ", value = " + verification_code)
    return verification_code

from main import db
from models import User, Poll, Poll_option, add_poll_func


'''def add_poll(title, user_id, options):
    if title != None and user_id != None and options != None:
        new_poll = Poll(title=title, user_id=user_id)
        try:
            db.session.add(new_poll)
            db.session.flush()
        except:
            db.session.rollback()
        options_list = options.split("\n")
        for option in options_list:
            poll_option = Poll_option(poll_id=new_poll.id, user_id=user_id, answer=option, votes=0)
            #print(f'adding new poll option: {poll_option}')
            try:
                db.session.add(poll_option)
                db.session.flush()
            except:
                db.session.rollback()
        db.session.commit()'''

'''user = User(username="Dude", email="email@example.com")
user.set_password("P@ssword")
try:
    db.session.add(user)
    db.session.commit()
except:
    db.session.rollback()'''

add_poll_func(title="Yes or no?", user_id=1, options="No\nYes")
new_poll_1 = Poll.query.filter_by(id=1).first()


add_poll_func(title="Can you answer question to question?",
         user_id=1,
         options="Why are you asking?\nDoes it matter?")

new_poll_2 = Poll.query.filter_by(id=2).first()


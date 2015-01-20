import os.path
path = os.path.dirname(os.path.abspath(__file__))

import tornado.web
import tornado.options
import pymongo
import re
import json
import logging

from collections import namedtuple
from tornado.options import define, options
from tornado.web import StaticFileHandler, Application

import vv

from dateutil.relativedelta import relativedelta

def one_year_from(date):
    return date + relativedelta(years=1)

def three_months_from(date):
    return date + relativedelta(months=3)

with open(os.path.join(path, "member.vv")) as f:
    MEMBER_VV = vv.Parser(f).parse()

define("config_file", type=str)

db = pymongo.MongoClient()

SLUG_REGEX = re.compile(r"^[a-z][a-z0-9-]*$")

logger = logging.getLogger()

def validate_slug(slug):
    return SLUG_REGEX.match(slug) is not None

def create_app(config_file):
    with open(config_file) as f:
        config = json.load(f)

    base_dir = config['global']['base_dir']

    routes = []
    logger.debug("Routes:")

    for endpoint in config['endpoints']:
        route_type = endpoint['type']

        if route_type not in ['membership']:#, 'survey', 'poll']:
            logger.critical("Invalid route type: %r; ignoring." % route_type)
            continue

        name = endpoint['name']

        if not validate_slug(name):
            logger.critical("Invalid slug: %r; ignoring." % name)
            continue

        database_str = endpoint['database']
        collection_str = endpoint['collection']

        collection = db[database_str][collection_str]

        tmpl_path = r"%s/%s/templates" % (base_dir, name)

        if route_type == "membership":
            args = dict(config=config,
                        collection=collection,
                        template_path=tmpl_path)
            static_path = r"%s/%s/static" % (base_dir, name)
            new_routes = [
                (r'/%s' % name, MembershipHandler, args),
                (r'/%s/static' % name, StaticFileHandler, dict(path=static_path)),
                (r'/%s/([a-f0-9]{32})/login' % name, MembershipAuthHandler, args),
                (r'/%s/([a-f0-9]{32})/confirm' % name, MembershipEmailConfirmationHandler, args),
                (r'/%s/([a-f0-9]{32})' % name, MembershipUpdateHandler, args)
            ]

            for route in new_routes:
                logger.debug("  %s" % route[0])
            logger.debug("  [tmpl path]: %s" % tmpl_path)
            routes += new_routes

    logger.debug("Routes done.")

    return Application(routes)

class Member:
    def __init__(self, record):
        self._record = record

    @property
    def needs_renewal(self):
        now = datetime.datetime.now()
        if self._record['details'].get('expires_on', None) is None:
            return True
        return now <= self._record['details']['expires_on']

    @property
    def membership_level(self):
        return self._record['details']['membership_level']


class PINPayment(Payment):
    def is_invoice_required(self):
        return False

class BaseHandler(tornado.web.RequestHandler):
    def initialize(self, config, collection, template_path):
        self.config = config
        self.collection = collection
        self.template_path = template_path

    def get_template_path(self):
        return self.template_path

    def get_current_user(self):
        # ~15 minutes
        return self.get_secure_cookie("user", max_age_days=0.0141666)


# /membership
class MembershipHandler(BaseHandler):
    def create_validation_model(self, data):
        return MEMBER_VV(data)
        # Get schema, create generator
        # Generate a model for validation

    def get_membership_data(self, member_id):
        logger.debug("[get_membership_data] %r" % member_id)
        return self.collection.find_one({"_id": uuid.UUID(member_id)})

    def update_membership_data(self, member_id, **args, **kwargs):
        logger.debug("[update_membership_data] %r" % (args))
        return self.collection.update({"_id": uuid.UUID(member_id)},
                *args, **kwargs)

    def set_membership_details(self, member_id, details_data):
        self.collection.update({"id": member_id}, {
            "$set": {
                "details": details_data,
            }
        })

        # TODO add audit information as well

    def create_new_member(self, data, payment):
        while True:
            member_id = uuid.uuid4()
            if self.get_membership_data(member_id) is None:
                break

        data['email_confirmed'] = uuid.uuid4().hex
        data['expires_on'] = one_year_from(datetime.datetime.now())

        o = {
            "_id": member_id,
            "details": data,
            "pending_payment": payment,
            "history": [{
                "action": "new",
                "ts": datetime.datetime.now(),
                "data": {
                    "details": data,
                    "pending_payment": payment
                },
                "user": "system"
            }],
            "v": 2
        }

        self.update_membership_data(member_id.hex, o)
        return o


    def is_email_unique(self, email_addr, member_id=None):
        if member_id is None:
            return self.collection.find_one({
                "details.email": email_addr}) is None
        else:
            return self.collection.find_one({
                    "details.email": email_addr,
                    "id": {"$not": member_id}
                }) is None

    def write_error(self, status_code, **kwargs):
        if status_code == 500:
            self.render('error500')
        else:
            self.render('error')

    def generate_payment(self, member_id, payment_data):
        payment_method = payment_data.get('payment_method')
        fee = payment_data.get('fee')
        donation = payment_data.get('donation')

        o = {
            "method": payment_method,
            "status": "unsent",
            "due_date": three_months_from(datetime.datetime.now()),
            "fee": fee,
            "donation": donation,
            "ts": datetime.datetime.now()
        }

        if payment_type == "direct_deposit":
            o['reference'] = self.generate_payment_ref()

        return o

    def process_payment(self, member_data, payment_data):
        if member_data.get('pending_payment', None) is None:
            logger.warning("No pending payment found for id %s" % member_id)
            return True

        pending = member_data['pending_payment']
        method = pending['method']

        member_id = member_data['_id'].hex

        if method == "credit":
            # Pin Payments yeah yeah
            ref = payment_data.get('pin_payments_ref', None)
            if ref is None:
                return [('pin_payments_ref', 'ref missing.')]

            member_data['pending_payment']['status'] = 'paid'

            self.update_membership_data(member_id, {
                {
                    "$set": { "pending_payment": None },
                    "$push": { "history": {
                        "action": "payment",
                        "ts": datetime.datetime.now(),
                        "data": member_data['pending_payment'],
                        "user": "system"
                    }}
                }
            })

            # TODO attempt to actually process this
        elif method == "paypal":
            # TODO paypal_id
            # TODO reference
            # TODO issued_date
            # TODO last_emailed
            pass

        elif method == "direct_deposit":
            # TODO send email.
            self.update_membership_data(member_id, {
                "$set": { "pending_payment.status": "sent",
                          "pending_payment.issued_date": datetime.datetime.now(),
                          "pending_payment.last_emailed": datetime.datetime.now() }
            })

        return True



    def post(self):
        """
        1. Receive data
        2. Validate data
        3. Store membership model in Mongo
        4. Generate invoice, or take payment
        5. Send email confirmation
        6. Render page
        """
        # Validate input, store if necessary
        # Process payments
        # Return good page of success

        # TODO XSRF check

        body = self.request.body_arguments
        model = self.create_validation_model(body)

        messages = []
        if not model.is_valid:
            messages += model.messages

        if model.fields['email'].is_valid:
            if not self.is_email_unique(body['email'], member_id):
                messages.append(("email", "Email address must be unique."))

        if len(model.extra) > 0:
            # Report the extra fields via email and add to database.
            pass

        if len(messages) > 0:
            self.render('failure', messages=messages)
            return

        # Process similarly to membership handler
        details = model.as_dict(group=None)
        payment_data = model.as_dict(group='payment')

        payment = self.generate_payment(payment_data)
        member_data = self.create_new_member(details, payment_data)
        self.set_secure_cookie('user', member_data['_id'])

        result = self.process_payment(member_data, payment_data)

        if not result:
            self.render('payment_failed')

        else:
            self.set_secure_cookie('user', None)
            self.render('success', update=False)

    def get(self):
        self.render('new')

class MembershipEmailConfirmationHandler(BaseHandler):
    def confirm_member(self, member_id):
        self.collection.update({"id": member_id}, {
            "$set": {"details.email_confirmation": True},
            "$push": {
                "history": {
                    "action": "email-confirmed",
                    "user": "system",
                    "data": { "details": { "email_confirmed": True } },
                    "ts": datetime.datetime.now()
                }
            }
        })

    def get(self, member_id):
        c = self.get_argument('c')
        data = self.get_membership_data()

        if data is None or c is None:
            self.finish()
            # TODO LOG THIS
            return

        if data.get('details', {}).get('email_confirmation', None):
            if c == data['details']['email_confirmation']:
                self.confirm_member(member_id)
                self.render('email_confirmed', dict(email=data['details']['email']))
            #else:
            #   #TODO LOG THIS
            #   pass

        self.finish()
        # TODO LOG THIS
        return


# /membership/<uuid>
class MembershipUpdateHandler(MembershipHandler):
    def post(self, member_id):
        if not self.current_user or self.current_user != member_id:
            self.set_secure_cookie('user', None)
            self.redirect(self.request.path + "/login")
            return

        # Refresh the cookie
        self.set_secure_cookie('user', member_id)

        record = self.get_membership_data(member_id)
        member = Member(record)

        body = self.request.body_arguments
        model = self.create_validation_model(body)

        if not model.is_valid:
            # Return errors and shit
            return # TODO

        if not self.is_email_unique(body['email'], member_id):
            # Surprise, have a fucking error.
            return # TODO

        if model.has_extra_fields:
            # Report the extra fields via email and add to database.
            return # TODO

        if body['membership_type'] != record['details']['membership_type']:
            # TODO Return 500 to look incompetent.
            # TODO email the admin that a dodgy prick tried to change their
            # membership type by form hacks.
            return

        if body['renewal'] != member.needs_renewal:
            # TODO haha another cunt getting in my way.
            # TODO email them for great ruin.
            return

        try:
            invoice = self.generate_invoice(member_id, body)
        except:
            # TODO log it
            # TODO email it
            # TODO return error
            return

        try:
            self.add_processing_invoice(member_id, invoice)
        except:
            pass
            # TODO log, email, err

        if invoice.process_now:
            self.process_invoice(invoice)

        # Process similarly to membership handler
        self.set_membership_details(model.dict())

        self.render('success', success=True)

    def get_form_settings(self, member_data):
        # Check if renewal required to continue
        #if something in member_data makes renewal required:
        #    renewal = the date it expired
        #else:
        #    renewal = None

        return dict(renewal=renewal, details=member_data['details'])

    def get(self, member_id):
        # Check if auth needed, if yes, auth redir.
        if not self.current_user or self.current_user != member_id:
            self.set_secure_cookie('user', None)
            self.redirect(self.request.path + "/login")
            return

        # Refresh the cookie
        self.set_secure_cookie('user', member_id)

        data = get_membership_data(member_id)

        # Else, return membership form with relevant data
        # Probably want to include when membership expires, that'd be fun
        form_settings = self.get_form_settings(data)
        self.render('update', **form_settings)

# /membership/<uuid>/login
class MembershipAuthHandler(BaseHandler):
    def validate_auth_data(self, provided_data, user_data):
        if provided_data.get('password', None) is not None:
            # TODO
            return False

        dob = user_data['details']['date_of_birth']
        surname = user_data['details']['surname']
        postcode = user_data['details']['postcode']
        phone = user_data['details']['primary_phone']

        if provided_data['dob'] == dob and\
           provided_data['surname'] == surname and\
           provided_data['postcode'] == postcode and\
           provided_data['phone'] == phone:
           return True
        return False

    def post(self, member_id):
        # Check that passed information is valid
        # If yes, redir

        data = self.get_membership_data(member_id)

        if data is not None and validate_auth_data(self.request.body, data):
            self.set_secure_cookie('user', data.member_id)
            self.redirect("/".join(self.request.path.split('/')[:-1]))
        else:
            self.render('auth', failed=True)

    def get(self, member_id):
        if self.current_user:
            self.redirect("/".join(self.request.path.split('/')[:-1]))
        # Return the form.
        self.render('auth', failed=False)

if __name__ == "__main__":
    tornado.options.parse_command_line()
    application = create_app(options.config_file)
    application.listen(8888)
    tornado.ioloop.IOLoop.instance().start()


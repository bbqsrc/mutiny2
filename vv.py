import io
import re
import json
import datetime

from collections import namedtuple, OrderedDict

from lxml import etree
from lxml.etree import Element, SubElement


TypeToken = namedtuple("Type", ['name', 'children'])
ExtendsToken = namedtuple("Extends", ['type'])
ValidateToken = namedtuple("Validate", ['mode', 'args'])
MessageToken = namedtuple("Message", ['type', 'text'])
FieldToken = namedtuple("Field", ['type', 'name', 'children'])
RequiredToken = namedtuple("Required", ['condition', 'value'])
TransientToken = namedtuple("Transient", [])
GroupToken = namedtuple("GroupToken", ['name'])

# Internal use only
TransformToken = namedtuple("Transform", ['transform'])

def _json_fallback(obj):
    if obj.__class__.__name__ == "SRE_Pattern":
        return obj.pattern
    return str(obj)

def parse_iso8601(value):
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")

def parse_timestamp(value):
    return datetime.datetime.utcfromtimestamp(int(value))

builtin_types = OrderedDict((
    ("text", TypeToken("text", [
        TransformToken(lambda x: str(x))
        ])),
    ("integer", TypeToken("integer", [
        ValidateToken("regex", [re.compile(r"^[\+-]?\d+$")]),
        TransformToken(lambda x: int(x))
        ])),
    ("boolean", TypeToken("boolean", [
        ValidateToken("in", ["true", "false"]),
        TransformToken(lambda x: True if x == "true" else False)
        ])),
    ("date", TypeToken("date", [
        ValidateToken("regex", [
            re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")]),
        TransformToken(parse_iso8601)
        ])),
    ("time", TypeToken("time", [
        ValidateToken("regex", [re.compile(r"^\d+$")]),
        TransformToken(parse_timestamp)
        ])),
    ("email", TypeToken("email", [
        ExtendsToken("text"),
        ValidateToken("regex", [re.compile(r"^.+@.+\..+$")])
        ]))
))

class CalcExpression:
    def __init__(self, expr):
        if CALC_REGEX.match(expr) is None:
            raise ValueError("Invalid calc supplied: '%s'" % expr)
        self._expr = expr
        ns = {}
        exec("x = lambda x: %s" % expr, None, ns)
        self._lambda = ns['x']
    def __call__(self, x):
        return self._lambda(x)
    def __str__(self):
        return self._expr


class FieldNode:
    def __init__(self, model, name, value):
        self._model = model
        self._name = name
        self._value = value

        self._field_validator = self._model._ctx._field_validators[name]

    @property
    def group(self):
        return self._field_validator._group

    @property
    def is_valid(self):
        return self._field_validator._validate(self._value)

    @property
    def messages(self):
        # TODO this returns them all...
        return self._field_validator._messages

    @property
    def is_required(self):
        return self._field_validator.required(self._model)

    @property
    def is_transient(self):
        return self._field_validator.transient

    @property
    def value(self):
        if self._field_validator._transform is not None:
            return self._field_validator._transform(self._value)
        else:
            return self._value

    @property
    def raw_value(self):
        return self._value

_null = {}

class FieldModel:
    def __init__(self, ctx):
        self._ctx = ctx
        self.fields = {}

    @property
    def is_valid(self):
        if len(self.missing) > 0:
            return False

        for f in self.fields.values():
            if not f.is_valid:
                return False
        return True

    @property
    def missing(self):
        x = []
        for k, v in self._ctx._field_validators.items():
            if v.required and k not in self.fields:
                x.append(k)
        return x

    @property
    def extra(self):
        x = []
        for k in self.fields:
            if k not in self._ctx._fields:
                x.append(k)
        return x

    @property
    def messages(self):
        x = []
        for f in self.fields.values():
            x += f.messages
        return x

    def as_dict(self, group=_null):
        x = {}
        for k, v in self._ctx._field_validators.items():
            if k not in self.fields:
                continue
            if v.transient:
                continue
            if group != _null and v.group != group:
                continue
            x[k] = self.fields[k].value
        return x

class ValidatorFactory:
    def __init__(self, tokens):
        self._fields = OrderedDict()
        self._types = OrderedDict()
        self._field_validators = OrderedDict()
        self._type_validators = OrderedDict()

        for tok in list(builtin_types.values()) + tokens:
            name = tok.name

            if isinstance(tok, TypeToken):
                self._types[name] = tok
                self._type_validators[name] = TypeValidator(self, tok)

            if isinstance(tok, FieldToken):
                self._fields[name] = tok
                self._field_validators[name] = TypeValidator(self, tok)

    def __call__(self, data):
        model = FieldModel(self)

        for k, v in data.items():
            model[k] = FieldNode(model, k, v)

        return model

    # TODO: this really doesn't belong here.
    def create_validate(self, validate_token):
        mode = validate_token.mode

        if mode == "regex":
            return ValidateRegex(validate_token)
        elif mode == "date-less-than":
            return ValidateDateLessThan(validate_token)
        elif mode == "in":
            return ValidateList(validate_token)
        elif mode == "calc":
            return validate_token.args[0]
        elif mode == "value":
            return ValidateValue(validate_token)
        else:
            raise ValueError(validate_token)

class ValidateValue:
    def __init__(self, validate_token):
        self._val = validate_token.args[0]
    def __call__(self, value):
        return self._val == value

class ValidateRegex:
    def __init__(self, validate_token):
        self._regex = validate_token.args[0]
    def __call__(self, value):
        return self._regex.match(value) is not None

class ValidateList:
    def __init__(self, validate_token):
        self._args = validate_token.args
    def __call__(self, value):
        print("[ValidateList:(ret)] %r" % value in self._args)
        return value in self._args

class ValidateDateLessThan:
    def __init__(self, validate_token):
        self._c = validate_token.args[0]
        self._unit = validate_token.args[1]
    def __call__(self, value):
        raise NotImplementedError

class TypeValidator:
    def __init__(self, context, type_token):
        self.name = type_token.name
        self.context = context

        self._transform = None
        self._validate = lambda x: True
        self._messages = {}

        self._group = None
        self._transient = False
        self._required = False
        self._req_value = None

        # Handle field types
        if hasattr(type_token, 'type'):
            self._apply(context._types[type_token.type])

        self._apply(type_token)

    def _apply(self, type_token):
        for child in type_token.children:
            if isinstance(child, ExtendsToken):
                super_type_token = self.context._types[child.type]
                self._apply(super_type_token)
            elif isinstance(child, ValidateToken):
                self._validate = self.context.create_validate(child)
            elif isinstance(child, MessageToken):
                self._messages[child.type] = child.text
            elif isinstance(child, RequiredToken):
                if child.condition is None:
                    self._required = True
                else:
                    self._required = child.condition
                    self._req_value = child.value
            elif isinstance(child, TransientToken):
                self._transient = True
            elif isinstance(child, GroupToken):
                self._group = child.name
            elif isinstance(child, TransformToken):
                self._transform = child.transform
            else:
                raise Exception("Unknown token: %r" % child)

    def required(self, model):
        if isinstance(self._required, bool):
            return self._required
        else:
            req_field_val = model[self._required].raw_value
            return req_field_val == self._req_value

    @property
    def transient(self):
        return self._transient

CALC_REGEX = re.compile(r"^[\-0-9x<=> ]+$")

class Parser:
    def __init__(self, data):
        self.buf = io.StringIO()
        self.data = data
        self.tokens = []
        self.types = list(builtin_types.keys())
        self.field_names = []

        self.line_start = True
        self.sep_chars = [' ', '\n', ';']
        self.last_ch = ''

    def tokenise(self):
        while True:
            word = self._read_word()
            #print('[tokenise:word] %r' % word)

            if word == '':
                break

            if word == 'type':
                self._read_typedef()

            elif word in self.types:
                self._read_type(word)

            else:
                # DOESNTW ORK YET
                raise Exception("Unknown word: '%s'" % word)

        return self.tokens

    def parse(self):#, field_data):
        #tokens = self.tokenise()
        #ctx = ValidatorContext(field_data)
        #
        #for tok in tokens:
        #    if isinstance(tok, TypeToken):
        #        ctx.register_type(tok)
        #    elif isinstance(tok, FieldToken):
        #        ctx.register_field(tok)
        #return ctx
        return ValidatorFactory(self.tokenise())

    def xml(self):
        tokens = self.tokenise()
        root = Element("root")
        types = SubElement(root, "types")
        fields = SubElement(root, "fields")

        for tok in tokens:
            if isinstance(tok, TypeToken):
                node = SubElement(types, "type", name=tok.name)
            elif isinstance(tok, FieldToken):
                node = SubElement(fields, "field", name=tok.name, type=tok.type)

            for c in tok.children:
                name = c.__class__.__name__.lower()
                dct = c._asdict()

                if isinstance(c, RequiredToken):
                    if c.condition is None:
                        del dct['condition']
                        del dct['value']
                    else:
                        dct['value'] = "true" if c.value is True else "false"

                if hasattr(c, 'args'):
                    args = dct['args']
                    del dct['args']
                    subnode = SubElement(node, name, **dct)
                    for arg in args:
                        SubElement(subnode, 'arg',
                                    type=type(arg).__name__).text =\
                                        str(json.loads(json.dumps(
                                            arg, default=_json_fallback)))
                else:
                    SubElement(node, name, **dct)

        return etree.tostring(root, pretty_print=True).decode()


    def json(self, pretty=False):
        tokens = self.tokenise()
        fields = OrderedDict()
        types = OrderedDict()

        for token in tokens:
            if isinstance(token, TypeToken):
                types[token.name] = {
                    #'name': token.name,
                }
                for c in token.children:
                    if isinstance(c, ExtendsToken):
                        types[token.name]['extends'] = c.type
                    elif isinstance(c, ValidateToken):
                        #if types[token.name].get('validate', None) is None:
                        #    types[token.name]['validate'] = []
                        types[token.name]['validate'] = {#.append({
                            "mode": c.mode,
                            "arguments": c.args
                        }#})
                    elif isinstance(c, MessageToken):
                        if types[token.name].get('messages', None) is None:
                            types[token.name]['messages'] = {}
                        types[token.name]['messages'][c.type] = c.text

            elif isinstance(token, FieldToken):
                fields[token.name] = {
                    "type": token.type,
                    #"name": token.name,
                }
                for c in token.children:
                    if isinstance(c, RequiredToken):
                        if c.condition is None:
                            fields[token.name]['required'] = True
                        else:
                            fields[token.name]['required'] = {
                                "condition": c.condition,
                                "value": c.value
                            }
                    elif isinstance(c, TransientToken):
                        fields[token.name]['transient'] = True
                    elif isinstance(c, GroupToken):
                        fields[token.name]['group'] = c.name

        o = OrderedDict((("types", types), ("fields", fields)))
        if pretty:
            return json.dumps(o, indent=4, default=_json_fallback)
        else:
            return json.dumps(o, separators=(',', ':'), default=_json_fallback)

    def _read_word(self, end=None):
        chunk = io.StringIO()
        c = 0
        if end is None:
            end = self.sep_chars

        while True:
            self.last_ch = ch = self.data.read(1)
            if ch == "#":
                read_until(self.data, ['\n'])
                continue
            if ch in end:
                if c == 0:
                    continue
                return chunk.getvalue()
            if ch == '':
                return chunk.getvalue()
            chunk.write(ch)
            c += 1

    def _read_typedef(self):
        type_name, end = read_until(self.data, ['{'])
        if end != '{':
            raise Exception("EOF reached before finding '{'")
        type_name = type_name.strip()
        print("[_read_typedef:type_name] %r" % type_name)

        tokens = self._read_typedef_props()

        print("[_read_typedef:TypeToken(...)] %r %r" % (type_name, tokens))
        self.tokens.append(TypeToken(type_name, tokens))
        self.types.append(type_name)

    def _read_type(self, field_type):
        field_name, end = read_until(self.data, [';', '{'])
        field_name = field_name.strip()
        #print("[_read_type:field_name] %r" % field_name)

        if end == ';':
            tokens = []
        else:
            tokens = self._read_type_props()

        print("[_read_type:FieldToken(...)] %r %r %r" % (field_type, field_name, tokens))
        self.tokens.append(FieldToken(field_type, field_name, tokens))
        self.field_names.append(field_name)

    def _read_prop(self):
        x = io.StringIO()
        args = []
        in_quotes = False
        escaped = False
        raw = False

        while True:
            ch = self.data.read(1)

            if ch == '':
                raise Exception("Premature EOF.")

            if ch == ';':
                break

            if ch == '/' and not escaped and self.last_ch != '\\':
                raw = not raw
                continue

            if ch == '[' and not escaped and not raw:
                list_data, end = read_until(self.data, [']'])

                if end != ']':
                    raise Exception("Unclosed list.")

                print("[_read_prop:list_data] %r" % list_data)
                args.append(json.loads("[%s]" % list_data))
                continue

            if ch == '"' and not escaped and not raw:
                in_quotes = not in_quotes
                v = x.getvalue()
                if len(v) > 0:
                    args.append(v)
                    x = io.StringIO()
                continue

            # TODO handle the weird \\\\ case
            if ch == '\\' and not escaped:
                if not raw:
                    escaped = True
                    continue

            x.write(ch)
            #print("[_read_prop:x.write(ch)] %r" % ch)

            if ch == ' ' and not in_quotes and not raw:
                args.append(x.getvalue().strip())
                x = io.StringIO()
                #print("[_read_prop:args.append:args] %r" % args)

            escaped = False
            self.last_ch = ch

        if in_quotes:
            raise Exception("Unclosed quotes.")

        v = x.getvalue()
        if len(v) > 0:
            args.append(v)

        print("[_read_prop:args] %r" % args)

        return args

    def _read_type_props(self):
        tokens = []
        labels = ['required', 'transient', 'group']

        while True:
            word = self._read_word()
            #print("[_read_type_props:word] %r" % word)

            if word == '}':
                break

            if word == '':
                raise Exception("Missing '}'!")

            elif word == 'required':
                text = [] if self.last_ch == ';' else self._read_prop()
                if len(text) not in (0, 4):
                    raise Exception("'required' takes 0 or 4 args.")
                if len(text) == 4:
                    if text[0] == "if" and text[2] == "is":
                        bool_val = bool(text[3])
                        tokens.append(RequiredToken(text[1], bool_val))
                    else:
                        raise Exception("'required' args must be of format: " +\
                                        "'if <arg> is <val>'.")
                else:
                    tokens.append(RequiredToken(None, None))

            elif word == 'transient':
                text = [] if self.last_ch == ';' else self._read_prop()
                if len(text) != 0:
                    raise Exception("'transient' takes 0 args.")
                tokens.append(TransientToken())

            elif word == 'group':
                text = [] if self.last_ch == ';' else self._read_prop()
                if len(text) != 1:
                    raise Exception("'group' takes 1 arg.")
                tokens.append(GroupToken(text[0]))
            else:
                raise Exception("No valid tokens found; expected %r" % labels)

        return tokens

    def _contains_word(self, string, words):
        longest = len(max(words, key=len))
        return string in words

    def _read_typedef_props(self):
        tokens = []
        labels = ['extends', 'validate', 'message']
        buf = io.StringIO()

        while True:
            word = self._read_word()
            #print("[_read_typedef_props:word] %r" % word)

            if word == '}':
                break

            if word == '':
                raise Exception("Missing '}'!")

            elif word == 'extends':
                text = self._read_prop()
                if len(text) != 1:
                    raise Exception("'extends' requires 1 arg.")
                tokens.append(ExtendsToken(text[0]))

            elif word == "validate":
                text = self._read_prop()
                args = []

                l = len(text)
                if l < 1:
                    raise Exception("'validate' requires at least 1 arg.")

                mode = text[0]
                if mode == 'regex':
                    if l != 2:
                        raise Exception("'validate regex' requires 1 arg.")
                    try:
                        regex = re.compile(text[1])
                    except:
                        raise Exception("Invalid regex '%s'" % text[1])
                    args = [regex]

                elif mode == 'in':
                    args = text[1]

                elif mode == 'calc':
                    code = " ".join(text[1:])
                    try:
                        method = CalcExpression(code)
                        args = [method]
                    except SyntaxError as e:
                        raise Exception("Invalid syntax supplied in calc.")

                elif mode == 'date-less-than':
                    if l != 3:
                        raise Exception("'validate date-less-than' requires 2 args.")
                    try:
                        c = int(text[1])
                    except:
                        raise Exception("Arg 1 must be an integer")

                    unit = text[2]
                    if unit not in ['years']:
                        raise Exception("Unit not supported: '%s'." % unit)
                    args = [c, unit]

                elif mode == 'value':
                    if len(text) != 2:
                        raise Exception("validate value accepts only 1 arg.")
                    args = [text[1]]

                else:
                    raise Exception("Unknown mode '%s'." % mode)

                tokens.append(ValidateToken(mode, args))

            elif word == "message":
                text = self._read_prop()
                if len(text) != 2:
                    raise Exception("'message' requires 2 args.")
                msg_type = text[0]
                msg_text = text[1]

                tokens.append(MessageToken(msg_type, msg_text))

            else:
                raise Exception("No valid tokens found; expected %r" % labels)
        return tokens

def read_until_not(buf, toks):
    x = io.StringIO()
    ch = buf.read(1)

    while ch != '' and ch in toks:
        x.write(ch)
        ch = buf.read(1)

    return x.getvalue(), ch

def read_until(buf, toks):
    x = io.StringIO()
    ch = buf.read(1)

    while ch != '' and ch not in toks:
        x.write(ch)
        ch = buf.read(1)

    return x.getvalue(), ch


def test():
    data = {
        "given_names": "Brendan",
        "surname": "Molloy",
        "date_of_birth": "1992-03-25T00:00:00Z",
        "declaration": "tre"
    }

    schema = open("example.valid")

    #tokens = Parser(schema).tokenise()
    #print(json.dumps([repr(tok) for tok in tokens], indent=2))

    print(Parser(schema).json(pretty=True))
    #factory = ValidatorFactory(Parser(schema).tokenise())

    #return Parser(schema).parse(data)

if __name__ == "__main__":
    test()

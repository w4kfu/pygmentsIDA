# -*- coding: utf-8 -*-

import re
from string import Template

from pygments.lexer import Lexer, RegexLexer, include, bygroups, using, \
     this, combined
from pygments.util import get_bool_opt, get_list_opt
from pygments.token import Text, Comment, Operator, Keyword, Name, String, \
     Number, Punctuation, Error, Literal
from pygments.scanner import Scanner

__all__ = ['IDALexer']

class IDALexer(RegexLexer):
    """
    For the output of 'IDA'
    """
    name = 'ida'
    aliases = ['ida']
    filenames = ['*.asm']
    mimetypes = ['text/x-ida']

    identifier = r'[a-zA-Z$._?][a-zA-Z0-9$._?#@~]*'
    lineprefixes = r'([a-zA-Z$._?][a-zA-Z0-9$._?#@~]*:[a-zA-Z0-9$._?#@~]*)|[0-9]*\s+'
    hexn = r'(?:0[xX][0-9a-fA-F]+|$0[0-9a-fA-F]*|[0-9]+[0-9a-fA-F]*h)'
    octn = r'[0-7]+q'
    binn = r'[01]+b'
    decn = r'[0-9]+'
    floatn = decn + r'\.e?' + decn
    string = r'"(\\"|[^"\n])*"|' + r"'(\\'|[^'\n])*'|" + r"`(\\`|[^`\n])*`"
    declkw = r'(?:res|d)[bwdqt]\s+|times|unicode'
    register = (r'r[0-9][0-5]?[bwd]|'
                r'[a-d][lh]|[er]?[a-d]x|[er]?[sb]p|[er]?[sd]i|[c-gs]s|st[0-7]|'
                r'mm[0-7]|cr[0-4]|dr[0-367]|tr[3-7]')
    type = r'byte|[dq]?word\s+'

    flags = re.IGNORECASE | re.MULTILINE
    tokens = {
        'root': [
            include('whitespace'),
            (r'^\s*%', Comment.Preproc, 'preproc'),
            (lineprefixes, Name.Label),
            (identifier + ':', Name.Label),
            (r'(%s)(\s+)(=)' % identifier,
                bygroups(Name.Constant, Keyword.Declaration, Keyword.Declaration),
                'instruction-args'),
            (declkw, Keyword.Declaration, 'instruction-args'),
            (identifier, Name.Function, 'instruction-args'),
            (r'[\r\n]+', Text)
        ],
        'instruction-args': [
	    (r'<', String, 'unicodestring'),
            (string, String),
            (hexn, Number.Hex),
            (octn, Number.Oct),
            (binn, Number),
            (floatn, Number.Float),
            (decn, Number.Integer),
            include('punctuation'),
            (register, Name.Builtin),
            (identifier, Name.Variable),
            (r'[\r\n]+', Text, '#pop'),
            include('whitespace')
        ],
        'preproc': [
            (r'[^;\n]+', Comment.Preproc),
            (r';.*?\n', Comment.Single, '#pop'),
            (r'\n', Comment.Preproc, '#pop'),
        ],
        'whitespace': [
            (r'\n', Text),
            (r'[ \t]+', Text),
            (r';.*', Comment.Single)
        ],
	'unicodestring': [
	    (r'>', String, '#pop'),
            (r'\\([\\abfnrtv"\']|x[a-fA-F0-9]{2,4}|[0-7]{1,3})', String.Escape),
            (r'[^\\"\n]+', String),
            (r'\\\n', String),
            (r'\\', String),
	],
        'punctuation': [
            (r'[,():\[\]]+', Punctuation),
	    (r'[~!%^&*+=|?:<>/-]', Operator),
            (r'[$]+', Keyword.Constant),
            (type, Keyword.Type),
            (declkw, Keyword.Declaration),
        ],
    }


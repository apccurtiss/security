#!/usr/bin/python
# -*- coding: utf-8 -*-
blob = """
        5�C�3{��SJ���a.�W>Fj�A7氍0��������o^g;ם5���if.X���4xZ��4
mt�E�D����k�z�^��Dڦ�M(ae�7���wrk��5�
{ͩ�����h$�u���cd�&�.�"""
from hashlib import sha256
sha = sha256(blob).hexdigest()
if sha == '1d2366178c26456c7505c6ae291ae7f075cc0a08befae82e2c7643b077177381':
    print "We come in peace."
elif sha == '38faf526c412e464e9c320e46ee2e8318edefe28bb309f3b5ccb60dd6eed406b':
    print "Prepare to be destroyed!"
else:
    print "Something went wrong!"

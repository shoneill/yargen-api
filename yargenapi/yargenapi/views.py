# -*- coding: utf-8 -*-
from django.http import HttpResponse
import json

def index(request):
    data = ''
    with open('test.yara', 'r') as myfile:
        data=myfile.read()
    output = {'output' : data}
    return HttpResponse(json.dumps(output), content_type='application/json')

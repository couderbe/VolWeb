from django import forms

class NodeDetails(forms.Form):
    uid = forms.CharField(max_length=255,widget=forms.TextInput())
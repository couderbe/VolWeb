from django import forms

from analyser.models import Rule


class NewRuleForm(forms.ModelForm):
    class Meta:
        model = Rule
        fields = ('title','enabled','file', 'os')
        widgets = {
             'title': forms.TextInput(attrs={'class':'form-control','placeholder': 'Rule title','required':'""'}),
             'enabled': forms.CheckboxInput(),
             'file' : forms.FileInput(attrs={'class': 'form-control','required':'""'}),
             'os' : forms.Select(attrs={'class':'form-control','required':'""'}),
         }

#This form is used when editing or deleting a Rule
class ManageRuleForm(forms.Form):
     rule_id = forms.CharField(max_length=100, widget=forms.TextInput(attrs={
        'class': 'd-none',}))

class DownloadRuleForm(forms.Form):
     id = forms.CharField(max_length=255, widget=forms.TextInput(attrs={
        'class': 'd-none','value':'n/a'}))

class VirustotalForm(forms.Form):
     id = forms.CharField(max_length=255, widget=forms.TextInput(attrs={
        'class': 'd-none','value':'n/a'}))

class ClamAVForm(forms.Form):
     id = forms.CharField(max_length=255, widget=forms.TextInput(attrs={
        'class': 'd-none','value':'n/a'}))
     model = forms.CharField(max_length=256)

class get_model_objectForm(forms.Form):
     model = forms.CharField(max_length=256)
     field = forms.CharField(max_length=256)
     object_id = forms.CharField(max_length=256)
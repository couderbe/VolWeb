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
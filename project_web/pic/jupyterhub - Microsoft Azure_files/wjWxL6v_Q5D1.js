define("MsPortalImpl.Controls/Fields/TriStateCheckBox",["require","exports","f","i","o","MsPortalImpl.Controls/Fields/Base/Field","Viva.Controls/Controls/Forms/Viva.CheckBox","Viva.Controls/Controls/Base/ValidationPlacements/Viva.DockedBalloon","Viva.Controls/Controls/Base/ValidationPlacements/Viva.Css","MsPortalImpl/Widgets/Widgets.Common"],(function(n,t,i,r,u,f,e,o,s,h){"use strict";var c;return (function(n){var t=jQuery,c=(function(n){function f(t,i,r){return n.call(this,t,i,r)||this}return __extends(f,n),f.prototype._initializeField=function(){n.prototype._initializeField.call(this);var t=this.element;t.addClass("azc-checkBoxField").addClass("azc-triStateCheckBox").addClass("fxc-CheckBoxField").toggleClass("azc-checkBoxField-inlineLabel",this.options.inlineLabel).toggleClass("azc-checkBoxField-small",this.options.boxSize===1);this._checkBoxInit();h.waitForBindings(t[0]).then((function(){var n="azc-checkbox-guid-"+i.getUniqueId();t.find("input").attr("id",n);t.find("label").attr("for",n)}))},f.prototype.dispose=function(){this._checkBoxWidget&&(this._checkBoxWidget.dispose(),this._checkBoxWidget=null,this._checkBoxViewModel=null);this._cleanElement("azc-checkBoxField","azc-triStateCheckBox","fxc-CheckBoxField","azc-checkBoxField-inlineLabel");n.prototype.dispose.call(this)},u.defineProperty(f.prototype,"options",{get:function(){return this._options},enumerable:!0,configurable:!0}),u.defineProperty(f.prototype,"validatableViewModel",{get:function(){return this._checkBoxViewModel},enumerable:!0,configurable:!0}),u.defineProperty(f.prototype,"validatableWidget",{get:function(){return this._checkBoxWidget},enumerable:!0,configurable:!0}),f.prototype._checkBoxInit=function(){var n=this.ltm,i=this._checkBoxViewModel=new e.ViewModel(this.vmBasicOption);i.isTriState=!0;i.validationPlacements.push(new s.Css(n),new o.DockedBalloon(n,o.DockedBalloon.defaultOptions));this._checkBoxElement=t(r.createElement("div"));this.appendControl(this._checkBoxElement);this.linkCheckBoxViewModels();this._addWidget(this._checkBoxWidget=new e.Widget(this._checkBoxElement,this._checkBoxViewModel));this.setupValidationBindings()},f.prototype.linkCheckBoxViewModels=function(){var n=this;this._checkBoxViewModel.value(this._getCheckboxWidgetValue(this.options._msPortalFxWidgetValue()));this.options._msPortalFxWidgetValue.subscribe(this.ltm,(function(t){var i=n._getCheckboxWidgetValue(t);n._checkBoxViewModel.value()!==i&&n._checkBoxViewModel.value(i)}));this._checkBoxViewModel.value.subscribe(this.ltm,(function(t){var i=n._getTriStateCheckboxValue(t);n.options._msPortalFxWidgetValue()!==i&&n.options._msPortalFxWidgetValue(i)}));this._checkBoxViewModel.canUserSetIndeterminate(this.options.canUserSetIndeterminate());this.options.canUserSetIndeterminate.subscribe(this.ltm,(function(t){n._checkBoxViewModel.canUserSetIndeterminate()!==t&&n._checkBoxViewModel.canUserSetIndeterminate(t)}));this._checkBoxViewModel.canUserSetIndeterminate.subscribe(this.ltm,(function(t){n.options.canUserSetIndeterminate()!==t&&n.options.canUserSetIndeterminate(t)}));this.linkValidatableControlViewModels()},f.prototype._getCheckboxWidgetValue=function(n){var t=null;switch(n){case 0:t=0;break;case 1:t=1;break;case 2:t=2}return t},f.prototype._getTriStateCheckboxValue=function(n){var t=null;switch(n){case 0:t=0;break;case 1:t=1;break;case 2:t=2}return t},f.prototype._createLabelAndSubLabel=function(){this.options.inlineLabel?(this._attachLabelAndSubLabel({emptyLabel:!0}),this._attachLabelAndSubLabel({inhibitSubLabel:!0,inlineLabel:!0,insertLabelBefore:this._checkBoxElement,ariaLabel:this.options.ariaLabel})):this._attachLabelAndSubLabel({ariaLabel:this.options.ariaLabel})},f})(f.FieldWidget);n.Widget=c})(c||(c={})),c}))
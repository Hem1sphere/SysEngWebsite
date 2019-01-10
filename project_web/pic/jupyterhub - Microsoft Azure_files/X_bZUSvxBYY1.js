define("MsPortalImpl.Controls/Fields/TextField",["require","exports","f","i","o","ko","MsPortalImpl.Controls/Fields/Base/Field","Viva.Controls/Controls/Forms/Viva.TextBox","Viva.Controls/Controls/Base/ValidationPlacements/Viva.Css","Viva.Controls/Controls/Base/ValidationPlacements/Viva.DockedBalloon","MsPortalImpl.Controls/Controls/Lists/Base/Controls.Lists.ActionHandler"],(function(n,t,i,r,u,f,e,o,s,h,c){"use strict";var l;return (function(n){var a=jQuery,t="azc-textField",l="fxc-TextField",v=(function(n){function e(t,i,r){return n.call(this,t,i,r)||this}return __extends(e,n),e.prototype._initializeField=function(){n.prototype._initializeField.call(this);this.element.addClass(t).addClass(l);this.textFieldInit()},e.prototype._createLabelAndSubLabel=function(){this._attachLabelAndSubLabel({ariaLabel:this._options.ariaLabel})},e.prototype.dispose=function(){this._textBoxWidget&&(this._textBoxWidget.dispose(),this._textBoxWidget=null,this._textBoxViewModel=null);this._cleanElement(t,l);n.prototype.dispose.call(this)},u.defineProperty(e.prototype,"options",{get:function(){return this._options},enumerable:!0,configurable:!0}),u.defineProperty(e.prototype,"validatableViewModel",{get:function(){return this._textBoxViewModel},enumerable:!0,configurable:!0}),u.defineProperty(e.prototype,"validatableWidget",{get:function(){return this._textBoxWidget},enumerable:!0,configurable:!0}),e.prototype.textFieldInit=function(){var n=this,t=this._textBoxViewModel=new o.ViewModel(this.vmBasicOption),l=t.lifetimeManager,u,e;t.events={};t.validationPlacements.push(new s.Css(l));t.validationPlacements.push(new h.DockedBalloon(l,h.DockedBalloon.defaultOptions));this.options.actionHandler&&(u=this.ltm,this._actionHandler=c.getOrCreateActionHandler(f.unwrap(this.options.actionHandler)),f.isObservable(this.options.actionHandler)&&this.options.actionHandler.subscribe(u,(function(t){n._actionHandler=c.getOrCreateActionHandler(t)})),this._textBoxViewModel.events.enterPressed=function(){var t=n._actionHandler();t&&f.unwrap(n.options.actionsEnabled)&&t.activateFirstItem()},this._textBoxViewModel.events.downPressed=function(){var t=n._actionHandler();t&&f.unwrap(n.options.actionsEnabled)&&t.focusFirstItem()},this._textBoxViewModel.events.focus=function(){var t=n._actionHandler();t&&f.unwrap(n.options.actionsEnabled)&&t.pseudoFocusFirstItem()},this._textBoxViewModel.events.blur=function(){var t=n._actionHandler();t&&t.pseudoBlurFirstItem()},this._actionHandler.subscribe(u,(function(n){n&&t.focused()&&n.pseudoFocusFirstItem()})));e=a(r.createElement("div"));this.appendControl(e);this.linkTextBoxViewModels();this._addWidget(this._textBoxWidget=new o.Widget(e,this._textBoxViewModel));this.setupValidationBindings();this.options.value.subscribeAndRun(this.ltm,(function(t){n.element.findByClassName("azc-input").toggleClass("fxc-inputhasvalue",!!t)}));this.options.showValidationsAsPopup&&i.require("MsPortalImpl/Controls/Helpers/ValidationPopup").then((function(t){n._popupWidget=new t.Widget(n.ltm,{targetElement:n.element.find(".azc-inputbox"),widget:n,validationResults:n._textBoxViewModel.validationResults})}))},e.prototype.linkTextBoxViewModels=function(){var n=this;this._textBoxViewModel.value=this.options._msPortalFxWidgetValue;this._textBoxViewModel.placeholder(this.options.emptyValueText());this.options.emptyValueText.subscribe(this.ltm,(function(t){n._textBoxViewModel.placeholder(t)}));this._textBoxViewModel.valueUpdateTrigger=this.options.valueUpdateTrigger;this._textBoxViewModel.readOnly=f.utils.wrap(this.options.readOnly);this._textBoxViewModel.spellcheck=f.utils.wrap(this.options.spellcheck);this._textBoxViewModel.onEnterPressed=function(t){n.options.onEnterPressed&&n.options.onEnterPressed(t)};this.linkValidatableControlViewModels()},e})(e.FieldWidget);n.Widget=v})(l||(l={})),l}))
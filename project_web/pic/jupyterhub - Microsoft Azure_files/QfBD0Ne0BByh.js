define("_generated/Less/MsPortalImpl/Controls/Controls.Essentials.css",["require","exports","o","module"],(function(n,t,i,r){"use strict";i.defineProperty(t,"__esModule",{value:!0});window.fx.injectCss(r,'.fxc-essentials-item .msportalfx-text-primary:hover,.fxc-essentials-viewall-button:hover{text-decoration:underline}.fxc-essentials{flex:0 0 auto}.fxc-essentials .fxc-disabled{pointer-events:none;cursor:default}.fxc-essentials .msportalfx-text-primary{padding:0;border:0;cursor:pointer}.fxc-essentials-accordion,.fxc-essentials-border{border-bottom-width:1px;border-bottom-style:solid}.fxc-essentials-container{position:relative}.fxc-essentials-border{padding-top:22px}.fxc-essentials-accordion{height:24px;line-height:24px;box-sizing:border-box}.fxc-essentials-accordion-text{flex:1 0 auto}.fxc-essentials-expand-icon{flex:1 1 auto;width:100%}.fxt-essentials-expand-svg{transform:rotate(180deg);margin-left:-83px}.fxc-essentials-expand-button{-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none;user-select:none;cursor:pointer;width:100%;height:100%;background:0 0;border:0;padding-left:25px;margin:0;display:-webkit-flex;display:flex;-webkit-align-items:center;align-items:center;font-size:13px;font-family:az_ea_font,"Segoe UI",wf_segoe-ui_semibold,"Segoe UI Semibold","Segoe WP Semibold","Segoe WP",Tahoma,Arial,sans-serif;font-weight:600}.fxc-essentials-collapse-button{cursor:pointer;width:100%;height:24px;border:0;padding:0;margin:0;display:block;position:absolute;bottom:1px;left:0;right:0}.fxc-essentials-column-container{padding-top:4px;width:100%}.fxc-essentials-column-container:after{content:" ";clear:both;display:block}.fxc-essentials-column{box-sizing:border-box;float:left;width:50%}.fxc-essentials-column.fxc-essentials-responsive{width:100%}.fxc-essentials-column[data-side=left] .fxc-essentials-item,.fxc-essentials-column[data-side=right] .fxc-essentials-item{clear:both}.fxc-essentials-column[data-side=responsive] .fxc-essentials-item{width:275px}.fxc-essentials-item{box-sizing:border-box;padding:4px 10px;margin:0 10px}.fxc-essentials-item.fxc-essentials-responsive{float:left}.fxc-essentials-item .fxc-copyablelabel-textbox .azc-input{font-size:13px;height:17px;line-height:17px}.fxc-essentials-item .fxs-copyfield-wrapper{height:100%}.fxc-essentials-item-loading{display:inline-block;width:17px;height:17px}.fxc-essentials-label-container .msportalfx-text-primary{display:inline;font-size:inherit}.fxc-essentials-label{font-size:13px;line-height:17px}.fxc-essentials-move{display:inline-block;margin-left:4px;font-size:13px;line-height:17px}.fxc-essentials-move-button{line-height:17px}.fxc-essentials-item-value-container{height:17px;padding-top:4px}.fxc-essentials-item-value-container:first-child{padding-top:0}.fxc-essentials-value-container{position:relative;height:17px;padding-right:25px;display:inline-block;max-width:100%}.fxc-essentials-value-container.fxs-copyfield-container.fxs-copyfield-copied .fxs-copyfield{width:24px}.fxc-essentials-value{white-space:nowrap;overflow:hidden;font-size:13px;height:17px;line-height:17px;display:inline-block;text-overflow:ellipsis;text-align:left;max-width:100%}.fxc-essentials-responsive .fxc-essentials-value-container{float:left;clear:both}.fxc-essentials-responsive .fxc-essentials-value{max-width:calc(275px - 25px)}.fxc-essentials-responsive .fxc-essentials-value-container-has-icon .fxc-essentials-value{max-width:calc(275px - 70px)}.fxc-essentials-value-icon{display:inline-block;width:17px;height:17px}.fxc-essentials-value-icon-left{margin-right:4px}.fxc-essentials-value-icon-right{margin-left:4px}.fxc-essentials-notags-button{height:17px}.fxc-essentials-tags-container{padding-top:5px}.fxc-essentials-tags-list{margin-top:2px;margin-left:-5px;width:100%}.fxc-essentials-viewall-button-container{clear:both;float:none;height:20px;width:100%;padding:10px 10px 0;margin:0 10px}.fxc-essentials-viewall-button{font-size:13px}.fxc-essentials-spread-out .fxc-essentials-item{display:-webkit-flex;display:flex;padding:5px 15px}.fxc-essentials-spread-out .fxc-essentials-label-container{-webkit-flex:0 0 auto;flex:0 0 auto;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.fxc-essentials-spread-out .fxc-essentials-item-label-splitter{-webkit-flex:0 0 15px;flex:0 0 15px;text-align:center}.fxc-essentials-spread-out .fxc-essentials-value-wrapper{-webkit-flex:1 0 auto;flex:1 0 auto}.fxc-essentials-spread-out .fxc-essentials-viewall-button-container{padding:10px 15px 0}.fxc-essentials-spread-out .fxc-essentials-tags-list{margin-top:0}.fxc-essentials-spread-out .fxc-essentials-tags-container .fxc-essentials-item-label-splitter,.fxc-essentials-spread-out .fxc-essentials-tags-container .fxc-essentials-label-container,.fxc-essentials-spread-out .fxc-essentials-tags-container .fxc-essentials-notags-button{margin-top:5px}.fxc-essentials-spread-out .fxc-essentials-tags-container .fxc-essentials-item{padding-top:0}')}));
define("MsPortalImpl/Controls/Controls.Essentials",["require","exports","f","i","o","ko","Fx/Controls/Pill","Fx/Controls/PillCollection","Fx/ResourceManagement","MsPortalImpl.Controls/Controls/Base/ViewModelBase","MsPortalImpl.Controls/Controls/ResourceFilterHelper","Viva.Controls/Util/Viva.Resize","MsPortalImpl/Resources/ImplScriptResources","MsPortalImpl/Base/Base.ArmIdHelpers","MsPortalImpl/Base/Base.EventTypes","MsPortalImpl/Base/Base.KnockoutExtensions.Copy","MsPortalImpl/Base/Base.Sanitization","MsPortalImpl/Base/Base.SvgHelper","MsPortalImpl/Svg/Library/Loading/EllipsisSquare.svg","_generated/Less/MsPortalImpl/Controls/Controls.Essentials.css","MsPortalImpl/Base/Base.KnockoutExtensions.Copy"],(function(n,t,i,r,u,f,e,o,s,h,c,l,a,v,y,p,w,b,k){"use strict";function ui(n){var s=n.linkId,h=n.side,t='"'+s+'-" + $index()',u="msportalfx-text-primary "+ot+" "+rt,c=ot+" "+rt,l=dt+" "+rt,a=hi+" "+ot+" "+rt,e=r.createElementStringLiteral("a",{"class":u,"data-bind":{fxclick:"$root._getOnClick($data.onClick)",text:"$data.value",attr:{id:t,"aria-labelledby":t,"aria-disabled":"$root.$disabled",tabindex:"$root.$tabIndex","aria-describedby":"$root._descId",title:"$root._encodeString($data.value())"},css:{"fxc-disabled":"$root.$disabled"}}}),i={resourceLink:r.createElementStringLiteral(KoIf,{condition:"$data.type === 5"},e),bladeLink:r.createElementStringLiteral(KoIf,{condition:"$data.type === 4"},e),callback:r.createElementStringLiteral(KoIf,{condition:"$data.type === 3"},r.createElementStringLiteral("button",{"class":u,"data-bind":{click:"$root._getOnClick($data.onClick)",clickBubble:"false",text:"$data.value",attr:{id:t,"aria-labelledby":t,"aria-disabled":"$root.$disabled",tabindex:"$root.$tabIndex","aria-describedby":"$root._descId",title:"$root._encodeString($data.value())"},css:{"fxc-disabled":"$root.$disabled"}}})),clickableLink:r.createElementStringLiteral(KoIf,{condition:"$data.type === 2"},r.createElementStringLiteral("a",{"class":u,href:"#","data-link":!0,"data-bind":{text:"$data.value",attr:{href:"$root._getOnClick($data.onClick).uri",target:"$root._getOnClick($data.onClick).target",id:t,"aria-labelledby":t,"aria-disabled":"$root.$disabled",tabindex:"$root.$tabIndex","aria-describedby":"$root._descId",title:"$root._encodeString($data.value())"},css:{"fxc-disabled":"$root.$disabled"}}})),text:r.createElementStringLiteral(KoIf,{condition:"$data.type === 1"},r.createElementStringLiteral("div",{role:"text","class":c,tabindex:"0","data-bind":{text:"$data.value",attr:{"aria-label":"$root._encodeString($data.value())","aria-describedby":"$root._descId",title:"$root._encodeString($data.value())"},css:{"fxc-disabled":"$root.$disabled"}}}))},v=r.createElementStringLiteral(Root,null,i.callback,i.clickableLink,i.resourceLink,i.bladeLink,i.text),y=r.createElementStringLiteral(KoIf,{condition:"$data.loading()"},r.createElementStringLiteral("div",{role:"text","class":l},b.getSvgReferenceOrFallBackToData(k).outerHTML)),p=r.createElementStringLiteral(KoIf,{condition:"!$data.loading() && !$data.valueExists()"},r.createElementStringLiteral("div",{role:"text","class":a,tabindex:"0","data-bind":{attr:{"aria-label":'"---"',"aria-describedby":"$root._descId"}}},"---")),o=function(n){var t=ti+" "+ti+"-"+(n===1?"left":"right"),i="$data.icon() && $data.icon().image && $data.icon().position === "+n;return r.createElementStringLiteral(KoIf,{condition:i},r.createElementStringLiteral("span",{"class":t,"data-bind":{image:"$data.icon().image"}}))},w=r.createElementStringLiteral("div",{"class":ni,"data-bind":{visible:"!$data.loading() && $data.valueExists()"}},o(1),v,o(2)),f;return r.createElementStringLiteral("div",{"class":"fxc-essentials-item-value-container","data-bind":{css:(f={},f[li]="$data.icon() && $data.icon().image",f),style:{width:"$root._"+h+"ItemValueMaxWidth"}}},y,p,w)}function vi(n){var t=(n||"").toLowerCase();return t.startsWith("hidden-")||t.startsWith("link:")}function yt(n){var u="fxc-label-"+nt(),o="fxc-link-"+nt(),i='"'+u+'-" + $index()',f='"'+o+'-" + $index()',s=i+' + " " + '+f,e="fxc-link-"+nt(),h=n==="responsive"?lt+" "+kt:lt,c=gt+" fxs-portal-subtext",t={label:r.createElementStringLiteral("label",{"class":c,"data-bind":{text:"label",attr:{id:i,title:"$data.label"}}}),moveResourceButton:r.createElementStringLiteral(KoIf,{condition:"$data.movableLabelExists"},r.createElementStringLiteral("span",{role:"presentation","class":"fxc-essentials-move"},"(",r.createElementStringLiteral("button",{"class":"msportalfx-text-primary fxc-essentials-move-button","data-bind":{click:"$root._getOnClick(movableOnClick)",clickBubble:"false",text:"$data.movableLabel",attr:{id:f,"aria-labelledby":s,"aria-disabled":"$root.$disabled",tabindex:"$root.$tabIndex"},css:{"fxc-disabled":"$root.$disabled"}}}),")")),item:r.createElementStringLiteral(KoIf,{condition:"!$data.lines"},ui({linkId:e,side:n})),multiLineItem:r.createElementStringLiteral(KoIf,{condition:"!!$data.lines"},r.createElementStringLiteral(KoForEach,{items:"$data.lines"},ui({linkId:e,side:n})))};return r.createElementStringLiteral("div",{"class":h,"data-side":n,tabindex:"-1","data-bind":{attr:{"aria-labelledby":i}}},r.createElementStringLiteral("div",{"class":at,"data-bind":{style:{width:"$root._"+n+"LabelMaxWidth"}}},t.label,t.moveResourceButton),r.createElementStringLiteral(KoIf,{condition:"$root._spreadOutLayout"},r.createElementStringLiteral("div",{"class":ii},":")),r.createElementStringLiteral("div",{"data-label":u,"class":ci},t.multiLineItem,t.item))}var pt,fi;u.defineProperty(t,"__esModule",{value:!0});var g=i.Base,nt=i.getUniqueId,wt=i.ViewModels.Controls.DockedBalloon,ei=i.ViewModels.Services.ResourceTypes,ut=window,et={containerWidthBaseline:945,labelMaxWidth:150,marginWidth:105},oi=275,tt=5,si=2,bt="fxc-essentials",it="fxc-essentials-accordion-toggle",st="fxc-essentials-expand-button",ht="fxc-essentials-collapse-button",ct="fxc-essentials-column",kt="fxc-essentials-responsive",lt="fxc-essentials-item",dt="fxc-essentials-item-loading",hi="fxc-essentials-item-empty",at="fxc-essentials-label-container",gt="fxc-essentials-label",ci="fxc-essentials-value-wrapper",ni="fxc-essentials-value-container",li="fxc-essentials-value-container-has-icon",ot="fxc-essentials-value",ti="fxc-essentials-value-icon",vt="fxc-essentials-viewall-button",ii="fxc-essentials-item-label-splitter",ri="fxc-essentials-spread-out",rt="fxs-portal-text",d=a.Controls.Essentials,ai=new g.Diagnostics.Log("MsPortalImpl/Controls/Controls.Essentials"),ft=i.isFeatureEnabled("fxclicklinks");pt=i.memoizeQ((function(n){return c.getLocations().then((function(t){var i=(n.location||"").toLowerCase();return(t.first((function(n){return n.name.toLowerCase()===i}))||{}).displayName||n.location}))}));fi=(function(n){function t(t,r,u){var e=n.call(this,t,r,u)||this,s,h,c;return e.fetchingResourceData=f.observable(!1),e.controlId=nt(),e.viewAll=f.observable(!1).extend({notify:"always"}),e.showViewAllButton=f.observable(!1),e.showTags=f.observable(!1),e.noTags=f.observable(!1),e.editTagsIcon=g.Images.Edit(),e._staticItems={left:[],right:[]},e._spreadOutLayout=f.observable(!1),e._leftLabelMaxWidth=f.observable("100%"),e._rightLabelMaxWidth=f.observable("100%"),e._leftItemValueMaxWidth=f.observable("100%"),e._rightItemValueMaxWidth=f.observable("100%"),e._descId=e.controlId+"-desc",e._ariaLive=f.observable(""),e._events=[],e._lastKnownContainerWidth=0,e._armData={resourceGroup:{value:f.observable(null),movableOnClick:f.observable(i.noop),onClick:f.observable(ft?{resourceIdPlaceHolder:!0}:i.noop)},status:{value:f.observable(null)},location:{value:f.observable(null)},subscriptionName:{value:f.observable(null),movableOnClick:f.observable(i.noop),onClick:f.observable(ft?{resourceIdPlaceHolder:!0}:i.noop)},subscriptionId:{value:f.observable(null)}},e.vm=r,s=e.vm.options,e.viewAllString=f.computed(e.ltm,(function(){return e.viewAll().toString()})),e.expandedString=f.computed(e.ltm,(function(){return(!!e.vm.expanded()).toString()})),e.collapseIcon=e._getExpandCollapseIcon(!1),e.expandIcon=e._getExpandCollapseIcon(!0),e._encodeString=i.encodeAttribute,e._columnCount=e._getColumnCount(),h=s.resourceId,h?(e.tagsPillList=o.create(e.ltm,{multipleRows:!1,theme:2,ariaLabel:d.tags,items:[]}),c=s.hiddenBuiltInTypes&&!!~s.hiddenBuiltInTypes.indexOf(6),e.showTags(!!s.includeTags&&!c),e._processAndRender(),e.vm.resource.subscribeAndRun(e.ltm,(function(n){e.fetchingResourceData(!0);g.Promises.cancelOnDispose(e.ltm,(function(){return n?e._getResourceInfo(n):Q(null)})().then((function(n){return n?Q(n):e.vm.options.skipResourceFetching?Q(null):e.vm.getResourceInfo(h,e.showTags())}))).then((function(n){e.resourceData=n;e.fetchingResourceData(!1);e._processItems();e._processTags()}))})),e.vm.newTags.subscribe(e.ltm,(function(n){e._processTags(n)}))):e._processAndRender(),e}return __extends(t,n),t.prototype._getColumnLabelMaxWidth=function(n){var i=this.element.find("."+ct+"[data-side='"+n+"']"),r=i.findByClassName(at),t=0;return r.each((function(){var i=$(this).children(),n=i[0].getBoundingClientRect().width;i.length>1&&(n+=i[1].getBoundingClientRect().width+4);n=Math.ceil(n);n>t&&(t=n)})),t>=et.labelMaxWidth?et.labelMaxWidth:t},t.prototype._spreadLayoutProcess=function(n){var t,i,r;if(this.element.findByClassName("fxc-essentials-column-container").css("display")!=="none")if(t=n?n:this.element[0].getBoundingClientRect().width,this._lastKnownContainerWidth=t,i=t/2,r=t>=et.containerWidthBaseline,r){var u=this._getColumnLabelMaxWidth("left"),f=this._getColumnLabelMaxWidth("right"),e=et.marginWidth/2,o=Math.floor(i-u-e),s=Math.floor(i-f-e);this.element.addClass(ri);this._leftLabelMaxWidth(u+"px");this._rightLabelMaxWidth(f+"px");this._leftItemValueMaxWidth(o+"px");this._rightItemValueMaxWidth(s+"px");this._spreadOutLayout(!0)}else this.element.removeClass(ri),this._leftLabelMaxWidth("100%"),this._rightLabelMaxWidth("100%"),this._leftItemValueMaxWidth("100%"),this._rightItemValueMaxWidth("100%"),this._spreadOutLayout(!1)},t.prototype.itemTypeDetector=function(n){var t=f.unwrap(n.onClick),i=typeof t;if(i==="function")return 3;if(i==="object"){if(t.hasOwnProperty("uri"))return 2;if(!ft)return 1;if(t.hasOwnProperty("bladeReference"))return 4;if(t.hasOwnProperty("resourceId")||t.hasOwnProperty("resourceIdPlaceHolder"))return 5}return 1},t.prototype._getOnClick=function(n){var i=f.unwrap(f.unwrap(n)),t,r;return i.hasOwnProperty("target")?(t=i,r=f.unwrap(t.uri)||"",{uri:w.sanitizeUri(r)?r:"",target:f.unwrap(t.target),onLinkOpened:f.unwrap(t.onLinkOpened)}):i},t.prototype._getExpandCollapseIcon=function(n){return'<svg width="8" height="8" viewBox="0 0 8 8.4" focusable=\'false\' aria-hidden=\'true\' class=\'fxt-essentials-'+(n?"expand":"collapse")+'-svg\'><g data-name="Layer 2"><g data-name="Layer 1"><polygon points="4 3.7 0 7.7 0.7 8.4 4 5 7.3 8.4 8 7.7 4 3.7" /><polygon points="4 0 0 4 0.7 4.7 4 1.4 7.3 4.7 8 4 4 0" /><\/g><\/g><\/svg>'},t.prototype.dispose=function(){this._checkExistsOrRegisterDestroyId(n.prototype.dispose)||(this._cleanElement(bt),n.prototype.dispose.call(this))},t.prototype.noTagsClickHandler=function(){this._getEditTagAction()()},t.prototype._getColumnCount=function(){return this.vm.options.responsiveColumns?Math.floor((this.element.width()-30)/oi):si},t.prototype._getResourceInfo=function(n){var r=this,t=s.ArmId.parse(n.id);return v.isResourceAtAnyLevel(t)?pt(n).then((function(u){var f=t.subscription?i.Azure.getSubscriptionInfo(t.subscription):Q(null);return f.then((function(i){return{resourceGroupName:t.resourceGroup,resourceGroupId:s.ArmId.stringify(t,4),subscriptionName:i&&i.displayName,subscriptionId:i&&t.subscription,location:u,tags:r._userModifiedTags?r._userModifiedTags:n.tags,zones:n.zones,moveOptions:{resourceGroup:!0,subscription:!0}}}))})):t.kind===4?pt(n).then((function(u){return i.Azure.getSubscriptionInfo(t.subscription).then((function(i){return{resourceGroupName:t.resourceGroup,resourceGroupId:n.id,subscriptionName:i.displayName,subscriptionId:t.subscription,location:u,tags:r._userModifiedTags?r._userModifiedTags:n.tags,moveOptions:{resourceGroup:!1,subscription:!0}}}))})):Q(null)},t.prototype._generateTags=function(){var t=this.vm.options,e=t.hiddenChangeLink&&~t.hiddenChangeLink.indexOf(6),n="fxc-label-"+nt(),u="fxc-link-"+nt(),o='"'+n+" "+u+'"',f='"'+n+'"',s='"'+u+'"',h=gt+" fxs-portal-subtext",c=dt+" "+rt,l='"'+n+'-tags"',a=r.createElementStringLiteral("div",{"class":at,"data-bind":{style:{width:"$root._leftLabelMaxWidth"}}},r.createElementStringLiteral("label",{"class":h,"data-bind":{attr:{id:f}}},i.encodeHtml(d.tags)),e?null:r.createElementStringLiteral("span",{role:"presentation","class":"fxc-essentials-move"},"(",r.createElementStringLiteral("button",{"class":"msportalfx-text-primary","data-bind":{click:"$root._getEditTagAction()",clickBubble:"false",attr:{id:s,"aria-labelledby":o,"aria-disabled":"$root.$disabled",tabindex:"$root.$tabIndex"},css:{"fxc-disabled":"$root.$disabled"}}},i.encodeHtml(d.change)),")")),v=r.createElementStringLiteral(KoIf,{condition:"fetchingResourceData()"},r.createElementStringLiteral("div",{role:"text","class":c},b.getSvgReferenceOrFallBackToData(k).outerHTML)),y=r.createElementStringLiteral(KoIf,{condition:"noTags"},r.createElementStringLiteral("button",{"class":"msportalfx-text-primary fxc-essentials-notags-button","data-bind":{click:"noTagsClickHandler",clickBubble:"false",visible:"!fetchingResourceData()",attr:{"aria-disabled":"$root.$disabled",tabindex:"$root.$tabIndex"},css:{"fxc-disabled":"$root.$disabled"}}},i.encodeHtml(d.noTagsLabel))),p=r.createElementStringLiteral(KoIfNot,{condition:"noTags"},r.createElementStringLiteral("div",{"class":"fxc-essentials-tags-list","data-bind":{pcControl:"tagsPillList",visible:"!fetchingResourceData()"},"data-label":f}));return r.createElementStringLiteral("div",{"class":lt,tabindex:"-1","data-bind":{attr:{"aria-labelledby":l}}},a,r.createElementStringLiteral(KoIf,{condition:"$root._spreadOutLayout"},r.createElementStringLiteral("div",{"class":ii},":")),v,y,p)},t.prototype._attachCopyableLabel=function(){for(var t=this.element.find("."+ni+" > ."+ot),i,u=function(n){var u=t.eq(n),f;if(!u.hasClass("fxs-copyfield-wrapper")&&u.data("copyable")!=="true"){u.data("copyable","true");p.initializeCopyBinding(u.parent()[0],(function(){return u.text()}),{hideTextbox:!0});f=r;u.on(y.default.keyup,i=function(n){var r=n.ctrlKey||n.metaKey,i,t;r&&n.keyCode===67&&(i=ut.document.createRange(),i.selectNodeContents($(this).get(0)),t=ut.getSelection(),t.removeAllRanges(),t.addRange(i),ut.document.execCommand("copy"),$(this).focus(),f._ariaLive(t.toString()+" "+d.copiedToClipboard))});r._events.push({element:u,event:y.default.keyup,handler:i})}},r=this,n=0;n<t.length;n++)u(n)},t.prototype._getEditTagAction=function(n){var t=this;return function(){var i={resourceId:t.vm.options.resourceId,tag:n};t.vm.openBlade(6,i)}},t.prototype._createTagPill=function(n,t,r){var u=this,o=i.encodeHtml(t+" : "+r),f=new wt.ViewModel(n);return f.type=wt.Type.Info,f.content(o),e.create(n,{showRemoveButton:!1,getKeyText:function(n){return n.key},getOperatorText:function(){return":"},getValueText:function(n){return n.value},ariaLabel:o,value:{key:t,value:r},tooltip:f,createEditor:function(){return{onClick:function(){var n={resourceId:u.vm.options.resourceId,key:t,value:r};g.Promises.cancelOnDispose(u.ltm,u.vm.openBlade(1,n))}}}})},t.prototype._getTagItems=function(){var n=this;return i.forEachKey(this.resourceData&&this.resourceData.tags,(function(t,i,r){vi(t)||r.push(n._createTagPill(n.ltm,t,i))}),[])},t.prototype._processTags=function(n){if(n&&(this._userModifiedTags=n,this.resourceData.tags=n),this.showTags()){var t=this._getTagItems();this.tagsPillList.items(t);this.noTags(!t.length)}},t.prototype._attachLinkEvents=function(){var n=this,t=function(t,i){t.removeData("link");t.off(y.default.click+" "+y.default.keypress);var r=function(t){t===void 0&&(t=!0);var r=n._getOnClick(i),u=r.uri,e=r.target,f=r.onLinkOpened;u&&(window.open(u,e),f&&f(t))};n.ltm.registerForDispose(t.setEvents([y.default.click,function(){return r(!1),!1},],[y.default.keypress,function(n){return(n.which===13||n.which===32)&&r(!0),!1},]))};this.element.find("[data-link]").each((function(){var i=this,n=f.dataFor($(this)[0]);n.lines?n.lines.forEach((function(n){t($(i),n.onClick)})):n.onClick&&t($(this),f.unwrap(n).onClick)}))},t.prototype._throttleSpreadLayoutProcess=function(n){var t=this;ut.requestAnimationFrame((function(){t._spreadLayoutProcess(n)}))},t.prototype._processAndRender=function(){var n=this,t;this._processItems();this._processTags();t=function(t,r,u){u===void 0&&(u=!1);!n.vm.options.showAllItems&&(u&&t.length>n._columnCount*tt||!u&&t.length>tt)&&n.showViewAllButton(!0);n.vm.options.showAllItems||r||(u&&t.length>n._columnCount*tt?t=t.splice(0,n._columnCount*tt):!u&&t.length>tt&&(t=t.splice(0,tt)));var e=t.map((function(t){var u=i.initObservable(t.value),r={value:u,icon:i.initObservable(t.icon),loading:i.initObservable(t.loading),valueExists:f.computed(n.ltm,u,(function(n){return!i.isNullOrUndefined(n)})),movableLabelExists:t.movableLabelExists||!1};return t.lines?(r.type=n.itemTypeDetector(t),r.lines=t.lines.map((function(t){var r=i.initObservable(t.value);return __assign({},t,{type:n.itemTypeDetector(t),icon:i.initObservable(t.icon),value:r,loading:i.initObservable(t.loading),valueExists:f.computed(n.ltm,r,(function(n){return!i.isNullOrUndefined(n)}))})}))):r.type=n.itemTypeDetector(t),__assign({},t,r)}));return i.isFeatureEnabled("esselayout")&&!n.vm.options.responsiveColumns&&t.length&&n._throttleSpreadLayoutProcess(),e};this.vm.options.responsiveColumns?this._responsiveItems=f.computed(this.ltm,[this.vm.dynamicLeftArray,this.vm.dynamicRightArray,this.viewAll,],(function(i,r,u){return t(n._staticItems.left.concat(n._staticItems.right,i,r),u,!0)})):this._layout={left:f.computed(this.ltm,[this.vm.dynamicLeftArray,this.viewAll],(function(i,r){return t(n._staticItems.left.concat(i),r)})),right:f.computed(this.ltm,[this.vm.dynamicRightArray,this.viewAll],(function(i,r){return t(n._staticItems.right.concat(i),r)}))};this.element.addClass(bt);var e=~ut.navigator.platform.indexOf("Mac")?d.Copy.mac:d.Copy.win,o=""+st+(this.vm.expanded()?"":" "+it),s=""+ht+(this.vm.expanded()?" "+it:"")+" fxs-portal-hover",h=o+" fxs-portal-hover",c=r.createElementStringLiteral("div",{"class":"fxc-essentials-accordion fxs-portal-border","data-bind":{visible:"!vm.expanded()"}},r.createElementStringLiteral("button",{title:d.Label.expand,"aria-label":d.Label.expand,"aria-controls":this.controlId,"class":h,"data-bind":{attr:{"aria-expanded":"$root.expandedString","aria-disabled":"$disabled",disabled:"$disabled",tabindex:"$tabIndex"},click:"$root._toggleExpander",clickBubble:"false"}},r.createElementStringLiteral("div",{"class":[rt,"fxc-essentials-accordion-text"]},i.encodeHtml(d.essentials)),r.createElementStringLiteral("span",{"class":"fxc-essentials-expand-icon fxs-portal-svg","data-bind":{html:"$root.expandIcon"}}))),a=ct+" "+kt,u=ct,v=r.createElementStringLiteral("div",{id:this.controlId,"class":"fxc-essentials-column-container","aria-label":d.listProps,"data-bind":{visible:"$root.vm.expanded"}},r.createElementStringLiteral("div",{id:this._descId,"aria-hidden":"true","class":"fxs-hide-accessible-label"},e),r.createElementStringLiteral("div",{"aria-live":"polite","aria-atomic":"true","class":"fxs-hide-accessible-label","data-bind":{text:"$root._ariaLive"}}),!this.vm.options.responsiveColumns?r.createElementStringLiteral(Root,null,r.createElementStringLiteral("div",{"class":u,"data-bind":{foreach:"$root._layout.left"},"data-side":"left"},yt("left")),r.createElementStringLiteral("div",{"class":u,"data-bind":{foreach:"$root._layout.right"},"data-side":"right"},yt("right"))):r.createElementStringLiteral("div",{"class":a,"data-bind":{foreach:"$root._responsiveItems"},"data-side":"responsive"},yt("responsive"))),y=r.createElementStringLiteral(KoIf,{condition:"showTags"},r.createElementStringLiteral("div",{"class":"fxc-essentials-tags-container","data-bind":{visible:"$root.vm.expanded()"}},this._generateTags())),p="msportalfx-text-primary "+vt,w=r.createElementStringLiteral("div",{"class":"fxc-essentials-viewall-button-container","data-bind":{visible:"$root.vm.expanded() && $root.showViewAllButton()"}},r.createElementStringLiteral("button",{"class":p,role:"button","aria-controls":this.controlId,"data-bind":{attr:{"aria-disabled":"$root.$disabled","aria-expanded":"$root.viewAllString",tabindex:"$root.$tabIndex"},css:{"fxc-disabled":"$root.$disabled"}}},i.encodeHtml(this.viewAll()?d.seeLess:d.seeMore))),b=r.createElementStringLiteral("button",{"class":s,title:d.Label.collapse,"aria-label":d.Label.collapse,"aria-controls":this.controlId,"data-bind":{visible:"vm.expanded",attr:{"aria-expanded":"expandedString","aria-disabled":"$disabled",disabled:"$disabled",tabindex:"$tabIndex"},click:"_toggleExpander",clickBubble:"false"}},r.createElementStringLiteral("span",{"class":"fxs-portal-svg","data-bind":{html:"collapseIcon"}}));this._applyTemplate(r.createElementStringLiteral("div",{"class":"fxc-essentials-container"},c,v,y,w,r.createElementStringLiteral("div",{"class":"fxc-essentials-border fxs-portal-border","data-bind":{visible:"vm.expanded"}}),b));this._assignEvents();this.vm.options.responsiveColumns?(f.reactor(this.ltm,[this._responsiveItems],(function(){n._attachCopyableLabel()})),this._childLifetime=this.ltm.createChildLifetime(),l.track(this._childLifetime,this.element,(function(){var t=n._getColumnCount(),i;n._columnCount!==t&&(i=n.viewAll(),n._columnCount=t,n.showViewAllButton(!1),n._clearEvents(),n._childLifetime.dispose(),n.element.empty(),n._processAndRender(),n.viewAll(i))}))):f.reactor(this.ltm,[this._layout.left,this._layout.right],(function(){n._attachCopyableLabel();n._attachLinkEvents()}));i.isFeatureEnabled("esselayout")&&!this.vm.options.responsiveColumns&&l.track(this.ltm,this.element,(function(t){n._lastKnownContainerWidth!==t&&n._spreadLayoutProcess(t);n._lastKnownContainerWidth=t}),{ignoreInitialState:!0})},t.prototype._getResourceGroup=function(){var n=this,t=this.vm.options,r=t.hiddenChangeLink&&~t.hiddenChangeLink.indexOf(1),i=this._armData.resourceGroup,u=i.value,f=i.movableOnClick,e=i.onClick;if(this.resourceData){u(this.resourceData.resourceGroupName);var o=function(){if(n.resourceData.moveOptions&&n.resourceData.moveOptions.resourceGroup){var i={resourceId:t.resourceId,moveType:1};g.Promises.cancelOnDispose(n.ltm,n.vm.openBlade(1,i))}},s={resourceId:this.resourceData.resourceGroupId},h=function(){var t={resourceId:n.resourceData.resourceGroupId};g.Promises.cancelOnDispose(n.ltm,n.vm.openBlade(1,t))};f(o);e(ft?s:h)}return{label:d.resourceGroup,value:u,movableLabel:r?"":d.change,movableLabelExists:!r,movableOnClick:f,onClick:e,loading:this.fetchingResourceData}},t.prototype._getStatus=function(){var n=this._armData.status.value;return this.vm.status.subscribeAndRun(this.ltm,n),{label:d.status,value:n}},t.prototype._getLocation=function(){var t=this._armData.location.value,n,i;return this.resourceData&&(n=this.resourceData.location,this.resourceData.zones&&(i=d.zoneFormatString.format(this.resourceData.zones.join(d.zoneDelimiterString+" ")),n+=" ("+i+")"),t(n)),{label:d.location,value:t,loading:this.fetchingResourceData}},t.prototype._getSubscriptionName=function(){var n=this,t=this.vm.options,r=t.hiddenChangeLink&&~t.hiddenChangeLink.indexOf(4),i=this._armData.subscriptionName,u=i.value,f=i.movableOnClick,e=i.onClick;if(this.resourceData){u(this.resourceData.subscriptionName);var o=function(){if(n.resourceData.moveOptions&&n.resourceData.moveOptions.subscription){var i={resourceId:t.resourceId,moveType:0};g.Promises.cancelOnDispose(n.ltm,n.vm.openBlade(4,i))}},s={resourceId:"/subscriptions/"+this.resourceData.subscriptionId},h=function(){var t={resourceId:ei.buildSubscriptionFromId(n.resourceData.subscriptionId)};g.Promises.cancelOnDispose(n.ltm,n.vm.openBlade(4,t))};f(o);e(ft?s:h)}return{label:d.subscription,value:u,movableLabel:r?"":d.change,movableLabelExists:!r,movableOnClick:f,onClick:e,loading:this.fetchingResourceData}},t.prototype._getSubscriptionId=function(){var n=this._armData.subscriptionId.value;return this.resourceData&&n(this.resourceData.subscriptionId),{label:d.subscriptionId,value:n,loading:this.fetchingResourceData}},t.prototype._getItem=function(n){if(typeof n=="number")switch(n){case 1:return this._getResourceGroup();case 2:return this._getStatus();case 3:return this._getLocation();case 4:return this._getSubscriptionName();case 5:return this._getSubscriptionId();default:ai.error("Unknown BuiltInType is used (Illegal Access)")}return n},t.prototype._processItems=function(){var i=this,t=[],r=[],n=this.vm.options,u;switch(this.vm.optionType){case 1:u=[1,2,3,4,5,];n.hiddenBuiltInTypes&&n.hiddenBuiltInTypes.forEach((function(n){var t=u.indexOf(n);t>-1&&u.splice(t,1)}));u.forEach((function(n){t.push(i._getItem(n))}));n.additionalLeft&&(t=t.concat(n.additionalLeft));n.additionalRight&&(r=n.additionalRight);break;case 2:n.left.forEach((function(n){t.push(i._getItem(n))}));n.right.forEach((function(n){r.push(i._getItem(n))}));break;case 3:n.left.forEach((function(n){t.push(i._getItem(n))}));n.right.forEach((function(n){r.push(i._getItem(n))}))}this._staticItems.left=t;this._staticItems.right=r},t.prototype._toggleExpander=function(){var n=this.vm.expanded,t=this.vm.options.onExpanderClick,i=n();n(!i);i?this.element.findByClassName(ht).removeClass(it).end().findByClassName(st).addClass(it).focus():this.element.findByClassName(st).removeClass(it).end().findByClassName(ht).addClass(it).focus();t&&t(n())},t.prototype._applyTemplate=function(n){var t=$(n);this.element.append(t);f.applyBindings(this,t[0])},t.prototype._assignEvents=function(){var n=this,t=this.element.find("."+vt),i;t.on(y.default.click,i=function(){n.viewAll(!n.viewAll());var i=t;return i.html(i.html()===d.seeMore?d.seeLess:d.seeMore),!1});this._events.push({element:t,event:y.default.click,handler:i});this.ltm.registerForDispose((function(){n._clearEvents()}))},t.prototype._clearEvents=function(){this.element.find("."+vt).off(y.default.click);this._events.forEach((function(n){n.element.off(n.event,n.handler)}))},t})(h.Widget);t.Widget=fi}))
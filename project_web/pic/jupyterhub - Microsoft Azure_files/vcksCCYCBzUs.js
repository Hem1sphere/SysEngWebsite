define("MsPortalImpl/Base/Base.FeatureDetection",["require","exports","i","MsPortalImpl/Base/Base.EventTypes"],(function(n,t,i,r){"use strict";var u;return (function(n){function s(){if(!t){for(var f=1e8,r=1e4,u=$(i.createElement("div",{"class":"fxs-detect-maxheight",style:"position:fixed;right:-10px;bottom:-10px;width:10px"})).appendTo("body"),n=void 0,e=void 0;(e=f-r)>10;)n=0|r+e/2,u.height(n),n===(0|u.height())?r=n:f=n-1;t=r;u.remove()}return t}function e(){var t=$(i.createElement("div",{style:"position:fixed;right:-100px;bottom:-100px;width:10px;height:10px;overflow:scroll"})).appendTo("body"),n=t[0];f=n.offsetWidth-n.clientWidth;u=n.offsetHeight-n.clientHeight;t.remove()}function h(){return f||e(),f}function c(){return u||e(),u}var o=window,t,u,f;$(o).on(r.default.resize,(function(){t=0;u=0;f=0}));n.getMaxElementHeight=s;n.getScrollbarWidth=h;n.getScrollbarHeight=c})(u||(u={})),u}));
define("MsPortalImpl/UI/Commands/UI.Commands.Base",["require","exports","o"],(function(n,t,i){"use strict";i.defineProperty(t,"__esModule",{value:!0})}));
define("Viva.Controls/Util/Viva.TemplateEngine",["require","exports","f","i","o","ko","MsPortalImpl/Base/Base.LruMap"],(function(n,t,i,r,u,f,e){"use strict";var o;return (function(n){function o(n,t){var i=n.filter(t);return i.length||(i=n.find(t)),i}function h(n,t,i){var f=[],r;return n.forEach((function(n){f.push.apply(f,u(n))})),r=u(t),f.forEach((function(n){var u=n.key,t=n.value;r.some((function(n){var f=n.value,r;if(n.key===u)return r=t,i===0?r="{"+h([t],f,i+1)+"}":u==="class"&&(r="ko.unwrap("+f+')+" "+ko.unwrap('+t+")"),n.value=r,!0}))||r.push(n)})),r.map((function(n){return"'"+n.key+"':"+n.value})).join(",")}function c(n,t){var i=n.attr("data-bind"),r=h(t,i,0);n.attr("data-bind",r)}function p(n){var o=n[0].className,h=u(n.attr("data-bind")),i=[],s=[],r=0,e=!1,t;h.forEach((function(n){var t=n.key,r=n.value;t==="css"?u(r).forEach((function(n){"key"in n&&i.push("(ko.unwrap("+n.value+')?"'+n.key+'":"")')})):(t==="attr"&&u(r).some((function(n){return n.key==="class"}))&&(e=!0),s.push(n))}));i.length&&r++;e&&r++;e&&o!==""&&r++;r>=2&&(t=[],o!==""&&(t.push('"'+n[0].className+'"'),n[0].removeAttribute("class")),i.length&&(t.push.apply(t,i),n.attr("data-bind",f.expressionRewriting.preProcessBindings(s))),c(n,["attr:{'class':"+t.join('+" "+')+"}"]))}var t=jQuery,v=new e.LruMap(100),y=!i.isFeatureEnabled("nokosvgcaching"),u=f.expressionRewriting.parseObjectLiteral,l=(function(){function n(n,t){this._templateSources=n;this._key=t}return n.prototype.addAttribute=function(n,r,u){var f=t(this._get()),s=n?o(f,n):f,e=r;return typeof r=="string"&&(e={},e[r]=u),s.length&&(s.each((function(n,r){var u=t(r);i.forEachKey(e,(function(n,t){n==="data-bind"?c(u,t):n==="class"?u.addClass(t.join(" ")):u.attr(n,i.last(t))}));p(u)})),this._save(f)),this},n.prototype.html=function(n,i){var r=t(this._get());return o(r,n).html(i),this._save(r),this},n.prototype.prepend=function(n,i){var r=t(this._get());return o(r,n).prepend(i),this._save(r),this},n.prototype.append=function(n,i){var r=t(this._get());return o(r,n).append(i),this._save(r),this},n.prototype._get=function(){return this._templateSources[this._key]},n.prototype._save=function(n){for(var t,u,i="",r=0;r<n.length;r++)t=n[r],u=t.nodeType,u===8?i+="<!--"+t.nodeValue+"-->":u===1&&(i+=t.outerHTML);this._templateSources[this._key]=i},n})(),s,a;n.HtmlManipulation=l;s=(function(n){function u(){var t=n!==null&&n.apply(this,arguments)||this;return t._templateSources={},t}return __extends(u,n),u.prototype.getTemplate=function(n){return this._templateSources[n]},u.prototype.setTemplate=function(n,t){var r=this._templateSources;return typeof n=="string"?r[n]=t:i.extend(r,n),this},u.prototype.makeTemplateSource=function(n){var i=this._templateSources[n];return{nodes:function(){if(y){if(arguments.length===0)return v.getOrAdd(i,(function(){return t(r.createElement("div")).append(f.utils.parseHtmlFragment(i))[0]}));throw new Error("Can't set node");}},text:function(){var n=arguments.length===0;if(n&&i)return i;throw new Error(n?"Template name '"+name+"' does not exist.":"Can't set template");}}},u})(f.nativeTemplateEngine);n.StringTemplateEngine=s;a=(function(n){function t(){return n!==null&&n.apply(this,arguments)||this}return __extends(t,n),t.prototype.getHtmlTemplate=function(n){return new l(this._templateSources,n)},t})(s);n.HtmlTemplateEngine=a})(o||(o={})),o}))
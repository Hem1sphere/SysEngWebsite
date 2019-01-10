define("MsPortalImpl/Svg/Startup/SortArrows.svg",[],(function(){"use strict";return{type:1,data:"<svg viewBox='0 0 34.761 26.892' class='msportalfx-svg-placeholder' role='presentation' focusable='false' xmlns:svg='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink'><g><title><\/title><path d='M15.359 9.478l-6.226-6.21v17.557H7.426V3.268L1.2 9.478 0 8.281 8.279 0l8.279 8.281z' class='msportalfx-svg-c07 msportalfx-ascend'/><path d='M34.761 18.612l-8.279 8.281-8.282-8.281 1.2-1.2 6.226 6.21V6.068h1.707v17.557l6.226-6.21z' class='msportalfx-svg-c07 msportalfx-descend'/><\/g><\/svg>"}}));
define("_generated/Less/Viva.Controls/Util/Viva.Resize.css",["require","exports","o","module"],(function(n,t,i,r){"use strict";i.defineProperty(t,"__esModule",{value:!0});window.fx.injectCss(r,"@keyframes azc-resize-enter{0%{bottom:0}}@-webkit-keyframes azc-resize-enter{0%{bottom:0}}.azc-resize{animation:azc-resize-enter 1ms;-webkit-animation:azc-resize-enter 1ms;position:absolute;bottom:0;right:0;pointer-events:none;width:200%;height:200%;min-width:1px;min-height:1px;overflow:hidden;visibility:hidden}")}));
define("Viva.Controls/Util/Viva.Resize",["require","exports","f","i","o","MsPortalImpl/Base/Base.EventTypes","MsPortalImpl/Base/Base.Timers","_generated/Less/Viva.Controls/Util/Viva.Resize.css"],(function(n,t,i,r,u,f,e){"use strict";function d(){return!!c.ResizeObserver&&!!i.isFeatureEnabled("resizeobserver")}function g(n){return r.createElement("div",{"class":"azc-resize "+n},r.createElement("div",{"class":y}))}function s(n,t){return n.children("."+t)}function o(n){var t;return n&&n.endsWith("px")&&(t=parseFloat(n)),t||0}function nt(n){var t=getComputedStyle(l(n)[0],null),u=t.boxSizing==="border-box",r=o(t.width),i;return r&&u&&(r-=o(t.paddingLeft),r-=o(t.paddingRight)),i=o(t.height),i&&u&&(i-=o(t.paddingTop),i-=o(t.paddingBottom)),{width:r,height:i}}function tt(n){var t=nt(n);return{width:Math.round(t.width),height:Math.round(t.height)}}function it(n,t,i,r){var c=e.debounce(n,(function(t,r){e.requestAnimationFrame((function(){n.isDisposed()||i(t,r)}))}),100),u,f,o;if(h.has(t))throw new Error("Viva.Resize.track already registered for this element.");if(u=r&&r.ignoreInitialState,f={lifetime:n,handler:c,ignoreInitialState:u},h.set(t,f),p.observe(t),n.registerForDispose((function(){p.unobserve(t);h.delete(t)})),o=r&&r.notifyInitialSize,o&&!n.isDisposed()){var s=tt(t),l=s.width,a=s.height;i(l,a)}}function rt(n,t,i,r){function ht(){var r=tt(t),f=r.width,e=r.height,s=f!==rt||e!==ut,n,i;if(rt=f,ut=e,ft||s||!st){et.css({"min-width":"1px","min-height":"1px"});var h=nt(u),c=Math.floor(h.width),l=Math.floor(h.height);if(c){n=0;do n++,et.width(c+n),u.scrollLeft(u[0].scrollWidth);while(!u.scrollLeft()&&n<5)}if(l){i=0;do i++,et.height(l+i),u.scrollTop(u[0].scrollHeight);while(!u.scrollTop()&&i<5)}at.css({width:"200%","min-width":"1px",height:"200%","min-height":"1px"});o.scrollLeft(o[0].scrollWidth);o.scrollTop(o[0].scrollHeight);st=!!u.scrollLeft()&&!!u.scrollTop()&&!!o.scrollLeft()&&!!o.scrollTop()}return ft=!1,s}function h(n,t){ft=ft||t;lt()}var ot,p,ct,lt;if(t.length!==1)throw new Error("Viva.Resize.track can only take a element with length of 1. Current element.length: "+t.length);if(d())return it(n,t[0],i,r);if(ot=r&&r.notifyInitialSize,s(t,v).length)throw new Error("Viva.Resize.track already registered for this element.");p=t.css(a);p===b&&t.css(a,"relative");t.append(g(k),g(v));var u=s(t,v),o=s(t,k),et=s(u,y),at=s(o,y),rt,ut,st=!1,ft=!0;ht();ot&&i(rt,ut);ct=e.throttleByAnimationFrame((function(){!n.isDisposed()&&ht()&&i(rt,ut)}));lt=e.debounce(n,ct,100);n.registerForDispose([u.setEvents([w,function(n){return h(n)},],[f.default.animationstart,function(n){return h(n,!0)},]),o.setEvents([w,function(n){return h(n)},]),l(c).setEvents([f.default.resize,function(n){return h(n,!0)},]),l(document).setEvents(["visibilitychange",function(n){var t=document.visibilityState;h(n,t?t==="visible":!0)},]),]);n.registerForDispose((function(){u.remove();o.remove();p===b&&t.css(a,p)}))}var h,p;u.defineProperty(t,"__esModule",{value:!0});var w=f.default.scroll,c=window,l=jQuery,a="position",b="static",v="azc-resize-grow",k="azc-resize-shrink",y="azc-resize-content";h=new i.Map;p=c.ResizeObserver?new c.ResizeObserver(function(n){for(var i=0,r=n;i<r.length;i++){var u=r[i],e=u.target,t=h.get(e);if(t){var o=t.lifetime,s=t.handler,c=t.ignoreInitialState,l=t.inited;if(s&&!o.isDisposed())if(c&&!l)t.inited=!0;else{var f=u.contentRect,a=Math.round(f.width),v=Math.round(f.height);t.handler(a,v)}}}}):null;t.ResizeObserverEnabled=d();t.track=rt}))
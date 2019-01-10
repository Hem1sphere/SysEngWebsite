define(["require", "exports", "vs/base/parts/tree/browser/treeImpl", "vs/base/common/winjs.base"], function (require, exports, treeImpl_1, winjs_base_1) {
    /*---------------------------------------------------------------------------------------------
     *  Copyright (c) Microsoft Corporation. All rights reserved.
     *  Licensed under the MIT License.
     *--------------------------------------------------------------------------------------------*/
    'use strict';
    Object.defineProperty(exports, "__esModule", { value: true });
    var DataSource = /** @class */ (function () {
        function DataSource() {
        }
        DataSource.prototype.getId = function (tree, element) {
            return element.uri;
        };
        DataSource.prototype.hasChildren = function (tree, element) {
            return element.isFolder;
        };
        DataSource.prototype.getChildren = function (tree, element) {
            return winjs_base_1.TPromise.wrap($.ajax(consoleUri + element.uri, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': accessToken,
                    'Accept': 'application/json'
                }
            }).done(function (res, textStatus, jqXHR) {
                if (jqXHR.status >= 200 && jqXHR.status <= 299) {
                    return jqXHR.promise()
                        .then(function (entries) {
                        entries.forEach(function (entry) { return entry.parent = element; });
                        return entries;
                    });
                }
                else {
                    throw res;
                }
            }));
        };
        DataSource.prototype.getParent = function (tree, element) {
            return element.parent;
        };
        return DataSource;
    }());
    var Renderer = /** @class */ (function () {
        function Renderer() {
        }
        Renderer.prototype.getHeight = function (tree, element) {
            return 22;
        };
        Renderer.prototype.getTemplateId = function (tree, element) {
            return 'explorer_entry';
        };
        Renderer.prototype.renderTemplate = function (tree, templateId, container) {
            var span = document.createElement('span');
            span.classList.add('explorer-entry');
            container.appendChild(span);
            return span;
        };
        Renderer.prototype.renderElement = function (tree, element, templateId, templateData) {
            templateData.textContent = element.name;
        };
        Renderer.prototype.disposeTemplate = function (tree, templateId, templateData) {
        };
        return Renderer;
    }());
    var Controller = /** @class */ (function () {
        function Controller() {
        }
        Controller.prototype.onClick = function (tree, element, event) {
            if (element.isFolder) {
                tree.toggleExpansion(element);
                return true;
            }
            document.dispatchEvent(new CustomEvent('show', {
                detail: {
                    component: 'editor',
                    arguments: {
                        fileUri: element.uri,
                        fileName: element.name
                    }
                }
            }));
            return true;
        };
        Controller.prototype.onContextMenu = function (tree, element, event) {
            return false;
        };
        Controller.prototype.onTap = function (tree, element, event) {
            return false;
        };
        Controller.prototype.onKeyDown = function (tree, event) {
            return false;
        };
        Controller.prototype.onKeyUp = function (tree, event) {
            return false;
        };
        return Controller;
    }());
    var Sorter = /** @class */ (function () {
        function Sorter() {
        }
        Sorter.prototype.compare = function (tree, element, otherElement) {
            if (element.isFolder && !otherElement.isFolder) {
                return -1;
            }
            if (!element.isFolder && otherElement.isFolder) {
                return 1;
            }
            return element.name.localeCompare(otherElement.name);
        };
        return Sorter;
    }());
    var tree = new treeImpl_1.Tree(document.getElementById('editor-explorer'), {
        dataSource: new DataSource(),
        renderer: new Renderer(),
        controller: new Controller(),
        sorter: new Sorter()
    });
    function show(folderUri) {
        document.getElementById('editor-explorer')
            .style.display = null;
        if (!tree.getInput() || folderUri !== tree.getInput().uri) {
            var root = {
                uri: folderUri,
                name: '<root>',
                isFolder: true,
            };
            tree.setInput(root);
        }
        tree.layout(600, 200);
    }
    exports.show = show;
    function refresh() {
        tree.refresh();
    }
    exports.refresh = refresh;
    function layout() {
        tree.layout();
    }
    exports.layout = layout;
});
//# sourceMappingURL=explorer.js.map
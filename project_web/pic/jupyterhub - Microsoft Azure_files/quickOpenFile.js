var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
define(["require", "exports", "vs/nls", "vs/base/common/filters", "vs/base/parts/quickopen/browser/quickOpenModel", "vs/base/parts/quickopen/common/quickOpen", "vs/editor/common/editorContextKeys", "vs/editor/standalone/browser/quickOpen/editorQuickOpen", "vs/editor/browser/editorExtensions"], function (require, exports, nls, filters_1, quickOpenModel_1, quickOpen_1, editorContextKeys_1, editorQuickOpen_1, editorExtensions_1) {
    /*---------------------------------------------------------------------------------------------
     *  Copyright (c) Microsoft Corporation. All rights reserved.
     *  Licensed under the MIT License.
     *--------------------------------------------------------------------------------------------*/
    'use strict';
    Object.defineProperty(exports, "__esModule", { value: true });
    var QuickOpenFileEntry = /** @class */ (function (_super) {
        __extends(QuickOpenFileEntry, _super);
        function QuickOpenFileEntry(highlights, file) {
            var _this = _super.call(this) || this;
            _this.file = file;
            _this.setHighlights(highlights);
            _this.file = file;
            return _this;
        }
        QuickOpenFileEntry.prototype.getLabel = function () {
            return this.file.basename;
        };
        QuickOpenFileEntry.prototype.getAriaLabel = function () {
            return nls.localize('ariaLabelEntry', "{0}, files", this.getLabel());
        };
        QuickOpenFileEntry.prototype.getDescription = function () {
            return this.file.dirname !== '.' ? this.file.dirname : '';
        };
        QuickOpenFileEntry.prototype.run = function (mode, context) {
            if (mode === quickOpen_1.Mode.OPEN) {
                document.dispatchEvent(new CustomEvent('show', { detail: {
                        component: 'editor',
                        arguments: {
                            fileUri: this.file.uri,
                            fileName: this.file.basename
                        }
                    } }));
                return true;
            }
            return false;
        };
        return QuickOpenFileEntry;
    }(quickOpenModel_1.QuickOpenEntry));
    var QuickOpenFileAction = /** @class */ (function (_super) {
        __extends(QuickOpenFileAction, _super);
        function QuickOpenFileAction() {
            return _super.call(this, nls.localize('quickOpenFileActionInput', "Type the name of a file you want to open"), {
                id: 'editor.action.quickOpenFile',
                label: nls.localize('QuickOpenFileAction.label', "Quick Open File"),
                alias: 'Quick Open File',
                precondition: null,
                kbOpts: {
                    kbExpr: editorContextKeys_1.EditorContextKeys.focus,
                    primary: 2048 /* CtrlCmd */ | 46 /* KEY_P */
                },
            }) || this;
        }
        QuickOpenFileAction.prototype.run = function (accessor, editor) {
            var _this = this;
            $.ajax(consoleUri + '/quickOpen' + currentFolderUri, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': accessToken,
                    'Accept': 'application/json'
                }
            }).done(function (res, textStatus, jqXHR) {
                if (jqXHR.status >= 200 && jqXHR.status <= 299) {
                    return jqXHR.promise().then(function (files) {
                        _this._show(_this.getController(editor), {
                            getModel: function (value) {
                                return new quickOpenModel_1.QuickOpenModel(_this.filesToEntries(value, files));
                            },
                            getAutoFocus: function (searchValue) {
                                return {
                                    autoFocusFirstEntry: true,
                                    autoFocusPrefixMatch: searchValue
                                };
                            }
                        });
                    });
                }
                else {
                    throw res;
                }
            });
        };
        QuickOpenFileAction.prototype.filesToEntries = function (searchValue, files) {
            var entries = [];
            for (var i = 0; i < files.length; i++) {
                var file = files[i];
                var highlights = filters_1.matchesFuzzy(searchValue, file.basename);
                if (highlights) {
                    entries.push(new QuickOpenFileEntry(highlights, file));
                }
            }
            return entries;
        };
        return QuickOpenFileAction;
    }(editorQuickOpen_1.BaseEditorQuickOpenAction));
    editorExtensions_1.registerEditorAction(QuickOpenFileAction);
    var currentFolderUri = '/files/~';
    function setCurrentFolder(folderUri) {
        currentFolderUri = folderUri;
    }
    exports.setCurrentFolder = setCurrentFolder;
});
//# sourceMappingURL=quickOpenFile.js.map
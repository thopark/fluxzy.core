"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InstallMenuBar = void 0;
var electron_1 = require("electron");
var InstallMenuBar = function () {
    electron_1.ipcMain.on('install-menu-bar', function (event, arg) {
        var menuItemConstructorOptions = arg;
        try {
            InstallEvents(menuItemConstructorOptions);
            var menu = electron_1.Menu.buildFromTemplate(menuItemConstructorOptions);
            electron_1.Menu.setApplicationMenu(menu);
        }
        catch (exc) {
            event.returnValue = exc;
            return;
        }
        event.returnValue = '';
    });
};
exports.InstallMenuBar = InstallMenuBar;
var menuClickEventHandler = function (menuItem, browserWindow, event) {
    var payload = {
        menuLabel: menuItem.label,
        menuId: menuItem.id
    };
    browserWindow.webContents.send('application-menu-event', payload);
};
var InstallEvents = function (menuConstructorOptions) {
    for (var _i = 0, menuConstructorOptions_1 = menuConstructorOptions; _i < menuConstructorOptions_1.length; _i++) {
        var item = menuConstructorOptions_1[_i];
        item.click = menuClickEventHandler;
        var subMenus = item.submenu;
        if (subMenus)
            InstallEvents(subMenus);
    }
};
//# sourceMappingURL=menu-prepare.js.map
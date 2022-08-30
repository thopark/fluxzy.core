import { BrowserWindow, ipcMain, Menu, MenuItem, MenuItemConstructorOptions } from "electron";


export interface IApplicationMenuEvent {
    menuLabel : string ; 
    menuId ? : string ; 
    checked ? : boolean ;
}

export const InstallMenuBar = () : void => {

    ipcMain.on('install-menu-bar', (event, arg) => {
        const menuItemConstructorOptions : MenuItemConstructorOptions [] = arg ; 
        try {
            InstallEvents(menuItemConstructorOptions);
            const menu = Menu.buildFromTemplate(menuItemConstructorOptions) ; 
            Menu.setApplicationMenu(menu);
            
        }
        catch (exc) {
            event.returnValue = exc;
            return; 
        }
    
        event.returnValue = '';
    
    }) ; 
}

const menuClickEventHandler = (menuItem : MenuItem, browserWindow : BrowserWindow, event : KeyboardEvent ) : boolean => {

    let payload : IApplicationMenuEvent = {
        menuLabel : menuItem.label, 
        menuId : menuItem.id,
        checked: menuItem.checked 
    };

    browserWindow.webContents.send('application-menu-event', payload);
    return false; 
}


const InstallEvents = (menuConstructorOptions : MenuItemConstructorOptions []) : void => {

    for (var item of menuConstructorOptions) {
        item.click = menuClickEventHandler

        const subMenus = item.submenu as MenuItemConstructorOptions [];

        if (subMenus)
            InstallEvents(subMenus) ; 
    }

}




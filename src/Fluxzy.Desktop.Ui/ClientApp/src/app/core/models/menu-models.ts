import { Menu, MenuItem, MenuItemConstructorOptions } from "electron";
import { arrayBuffer } from "stream/consumers";
import {EnvironmentInfo} from "../services/system-call.service";


export const FindMenu : (arrayf : MenuItemConstructorOptions [] , condition : (item : MenuItemConstructorOptions) => boolean ) => MenuItemConstructorOptions | null  =
    (array, condition) => {
        for (let item of array) {
            let option: MenuItemConstructorOptions = item;
            if (!option)
                continue;

            if (condition(option))
                return option;

            let children : MenuItemConstructorOptions [] = option.submenu  as MenuItemConstructorOptions []  ;

            if (children) {
                let result = FindMenu(children, condition);

                if (result)
                    return result;
            }
        }
        return null;
    }

export const FindMenuByName = (array : MenuItemConstructorOptions [] , name : string ) : MenuItemConstructorOptions => {
    return FindMenu(array, (item) => item.id === name);
}


export const GetMainMenuItems = (environmentInfo : EnvironmentInfo) : MenuItemConstructorOptions [] => {
    // browse menu in InternalGlobalMenuItems
    return [
        {
            label : 'File',
            submenu : [
                {
                    label : 'New',
                    id : 'new',
                    accelerator: environmentInfo.platform === 'darwin' ? 'Cmd+N' : 'Ctrl+N',
                },
                {
                    label : 'Open',
                    id : 'open',
                    accelerator: environmentInfo.platform === 'darwin' ? 'Cmd+O' : 'Ctrl+O',
                },
                {
                    id : 'open-recent',
                    label : 'Open recent files',
                    enabled : false,
                    submenu : []
                },
                {
                    type :  'separator'
                },
                {
                    label : 'Save',
                    id : 'save',
                    accelerator: environmentInfo.platform === 'darwin' ? 'Cmd+S' : 'Ctrl+S',
                },
                {
                    label : 'Save as',
                    id : 'save-as',
                    accelerator: environmentInfo.platform === 'darwin' ? 'Cmd+Shift+S' : 'Ctrl+Shift+S',
                },
                {
                    label : 'Save filtered exchanges as',
                    id : 'save-filtered',
                },
                {
                    label : 'Save selected exchanges as',
                    id : 'save-selected',
                },
                {
                    type :  'separator'
                },
                {
                    label : 'Export',
                    submenu : [
                        {
                            label : 'Export to HAR',
                            id : 'export-to-har',
                        },
                        {
                            label : 'Export to SAZ',
                            id : 'export-to-saz',
                        },
                    ]
                },
                {
                    type :  'separator'
                },
                {
                    label : 'Quit',
                    role : 'quit'
                },
            ]
        },
        {
            label : 'Edit',
            submenu : [
                {
                    id : 'select-all',
                    label : 'Select all',
                    accelerator: environmentInfo.platform === 'darwin' ? 'Cmd+A' : 'Ctrl+A',
                },
                {
                    id : 'invert-selection',
                    label : 'Invert selection',

                },
                {
                    type :  'separator'
                },
                {
                    id : 'delete',
                    label : 'Delete selected exchanges',
                    accelerator: 'Delete',
                },
                {
                    type :  'separator'
                },
                {
                    id : 'clear',
                    label : 'Clear all',
                },
                {
                    type :  'separator'
                },
                {
                    label : 'Search everywhere',
                    id : 'search-everywhere',
                    accelerator: environmentInfo.platform === 'darwin' ? 'Cmd+T' : 'Ctrl+T',
                },
                {
                    type :  'separator'
                },
                {
                    label : 'Create new tag',
                    id : 'create-tag'
                },
                {
                    id : 'tag',
                    label : 'Tag selected exchanges',
                },
                {
                    id : 'comment',
                    label : 'Comment selected exchanges',
                },
            ]
        },
        {
            label : 'Capture',
            submenu : [
                {
                    id : 'capture',
                    label : 'Start recording',
                    accelerator : 'F5',
                    icon : '',
                },
                {
                    id : 'capture-with-filter',
                    label : 'Start record with source filter',
                    accelerator : 'Ctrl+F5',
                    icon : '',
                },
                {
                    id : 'halt-capture',
                    label : 'Stop recording',
                    accelerator : 'Shift+F5',
                    icon : '',
                },
                {
                    type :  'separator'
                },
                {
                    label : 'Disable all rules',
                    id : 'disable-all-rules'
                },
            ]
        },
        {
            label : 'Live edit',
            submenu : [
                {
                    label : 'Catch all',
                    id : 'pause-all'
                },
                {
                    label : 'Catch with filter',
                    id : 'pause-all-with-filter'
                },
                {
                    label : 'Stop catching',
                    id : 'delete-all-filters'
                },
                {
                    type :  'separator'
                },
                {
                    label : 'Resume all pending requests',
                    id : 'continue-all'
                },
                {
                    label : 'Resume all pending requests and delete live edit filters',
                    id : 'disable-all'
                },
                {
                    type :  'separator'
                },
                {
                    label : 'Show live edit dialog',
                    id : 'breakpoint-window',
                    accelerator : 'F11',
                },
                {
                    label : 'Show active live edit filters',
                    id : 'show-catcher',
                },
            ]
        },
        {
            label : 'Settings',
            submenu : [
                {
                    label : 'Manage rules',
                    id : 'manage-rules'
                },
                {
                    label : 'Manage filters',
                    id : 'manage-filters'
                },
                {
                    type :  'separator'
                },
                {
                    label : 'Run certificate wizard',
                    id : 'certificate-wizard'
                },
                {
                    type :  'separator'
                },
                {
                    label : 'Proxy settings',
                    id : 'global-settings',
                    accelerator: environmentInfo.platform === 'darwin' ? 'Cmd+Alt+S' : 'Ctrl+Alt+S',
                },
            ]
        },
        {
            label : 'Help',
            submenu : [
                {
                    label : 'Online docs',
                },
                {
                    type :  'separator'
                },
                {
                    label : 'Dev tools',
                    role : 'toggleDevTools'
                },
                {
                    type :  'separator'
                },
                {
                    id : 'about',
                    label : 'About Fluxzy Desktop',
                },
            ]
        },
    ];
}


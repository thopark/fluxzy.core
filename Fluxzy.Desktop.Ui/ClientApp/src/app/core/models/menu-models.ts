import { Menu, MenuItem, MenuItemConstructorOptions } from "electron";
import { arrayBuffer } from "stream/consumers";



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


export const GlobalMenuItems : MenuItemConstructorOptions []=  [
    {
        label : 'File',
        submenu : [
            {
                label : 'New',
                id : 'new',
                accelerator: process.platform === 'darwin' ? 'Cmd+N' : 'Ctrl+N',
            },
            {
                label : 'Open',
                id : 'open',
                accelerator: process.platform === 'darwin' ? 'Cmd+O' : 'Ctrl+O',
            },
            {
                id : 'open-recent',
                label : 'Open recent',
                enabled : false,
                submenu : []
            },
            {
                type :  'separator'
            },
            {
                label : 'Save',
                id : 'save',
                accelerator: process.platform === 'darwin' ? 'Cmd+S' : 'Ctrl+S',
            },
            {
                label : 'Save as',
                id : 'save-as',
                accelerator: process.platform === 'darwin' ? 'Cmd+Shift+S' : 'Ctrl+Shift+S',
            },
            {
                type :  'separator'
            },
            {
                label : 'Import',
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
                accelerator: 'Ctrl+A',
            },
            {
                id : 'invert-selection',
                label : 'Invert selection',

            },
            {
                type :  'separator'
            },
            {
                id : 'duplicate',
                label : 'Duplicate selection',
                accelerator: 'Ctrl+D',
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
        ]
    },
    {
        label : 'Debug',
        submenu : [
            {
                label : 'Pause any requests',
                id : 'pause-all'
            },
            {
                label : 'Continue All',
                id : 'continue-all'
            },
            {
                label : 'Disable all breakpoints',
                id : 'disable-all'
            },
            {
                type :  'separator'
            },
            {
                label : 'Show breakpoint window',
                id : 'breakpoint-window',
                accelerator : 'F11',
            },
        ]
    },
    {
        label : 'Rule',
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
        ]
    },
    {
        label : 'Settings',
        submenu : [
            {
                label : 'Proxy settings',
                id : 'global-settings'
            },
            {
                type :  'separator'
            },
            {
                label : 'Run certificate wizard',
                id : 'certificate-wizard'
            }
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
                label : 'About',
            },
        ]
    },


];

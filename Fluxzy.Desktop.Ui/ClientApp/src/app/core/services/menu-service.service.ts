import { Injectable } from '@angular/core';
import { filter, map, Observable, Subject, tap } from 'rxjs';
import { IApplicationMenuEvent } from '../../../../app/menu-prepare';
import { GlobalMenuItems } from '../models/menu-models';
import { ElectronService } from './electron/electron.service';

@Injectable({
    providedIn: 'root'
})
export class MenuService {

    private applicationMenuEvents$ : Subject<IApplicationMenuEvent> ; 


    private nextOpenFile$ = new Subject<string>() ; 
    
    constructor( private electronService : ElectronService) {
        this.applicationMenuEvents$ = new Subject<IApplicationMenuEvent>(); 
     }

    public getApplicationMenuEvents() : Observable<IApplicationMenuEvent> {
        return this.applicationMenuEvents$.asObservable() ; 
    }

    public init() : void {
        if (this.electronService.isElectron){         
            this.electronService.ipcRenderer.sendSync('install-menu-bar', GlobalMenuItems) ; 

            this.electronService.ipcRenderer.on('application-menu-event',  (evt, message) => {
                const menuEvent : IApplicationMenuEvent  = message; 
                this.applicationMenuEvents$.next(menuEvent);
                console.log(menuEvent); 
            });

            this.applicationMenuEvents$.pipe(
                    filter(e => e.menuId === 'open') , 
                    map(e => this.electronService.ipcRenderer.sendSync('request-file-opening', null) as string),
                    tap(t => this.nextOpenFile$.next(t)),
            ).subscribe() ;

            this.applicationMenuEvents$.pipe(
                    filter(e => e.menuId === 'new') , 
                    tap(t => this.nextOpenFile$.next('')),
            ).subscribe() ;
        }
    }

    public getNextOpenFile() : Observable<string> {
        return this.nextOpenFile$ ;
    }

}

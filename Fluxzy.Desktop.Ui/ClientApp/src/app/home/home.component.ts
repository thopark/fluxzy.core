import { ChangeDetectorRef, Component, OnInit, ViewChild } from '@angular/core';
import { Router } from '@angular/router';
import { MenuItemConstructorOptions } from 'electron';
import { filter, tap } from 'rxjs';
import { ExchangeInfo } from '../core/models/auto-generated';
import { GlobalMenuItems } from '../core/models/menu-models';
import { ElectronService } from '../core/services';
import { MenuService } from '../core/services/menu-service.service';
import { DialogService } from '../services/dialog.service';
import { ExchangeSelectionService } from '../services/exchange-selection.service';
import { UiStateService } from '../services/ui.service';

@Component({
    selector: 'app-home',
    templateUrl: './home.component.html',
    styleUrls: ['./home.component.scss']
})
export class HomeComponent implements OnInit {

    public selectedExchange: ExchangeInfo;

    constructor(private router: Router, 
        private menuService : MenuService,
        private exchangeSelectionService : ExchangeSelectionService,
        private dialogService : DialogService,
        private cdr: ChangeDetectorRef) { }
    
    ngOnInit(): void {

        this.menuService.init(); 
        this.dialogService.init();

        this.exchangeSelectionService.getSelected()
            .pipe(
                    tap(t => this.selectedExchange = t),
                    // tap(t => console.log('yoi')),
                    // tap(t => console.log(this.selectedExchange )),
                    tap(t => setTimeout(() => this.cdr.detectChanges(),2)), // TODO : check issue here
            ).subscribe()
    }; 
    
}

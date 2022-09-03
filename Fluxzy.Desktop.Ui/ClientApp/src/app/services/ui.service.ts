import { HttpClient } from '@angular/common/http';
import { Inject, Injectable } from '@angular/core';
import {
    Observable,
    of,
    Subject,
    tap,
    take,
    map,
    filter,
    switchMap,
    combineLatest,
    distinct,
} from 'rxjs';
import {
    ExchangeBrowsingState,
    ExchangeState,
    FileState,
    UiState,
} from '../core/models/auto-generated';
import { MenuService } from '../core/services/menu-service.service';
import { ApiService } from './api.service';
import { ExchangeContentService } from './exchange-content.service';
import {
    ExchangeSelectedIds,
    ExchangeSelectionService,
} from './exchange-selection.service';

@Injectable({
    providedIn: 'root',
})
export class UiStateService {
    private uiState$: Subject<UiState> = new Subject<UiState>();

    constructor(
        private httpClient: HttpClient,
        private menuService: MenuService,
        private apiService: ApiService,
        private selectionService: ExchangeSelectionService,
        private exchangeContentService:  ExchangeContentService
    ) {
        this.refreshUiState();

        this.apiService.registerEvent('uiUpdate', (state: UiState) => {
            this.uiState$.next(state);
        });

        combineLatest([
            this.getUiState(),
            this.selectionService.getCurrentSelectedIds(),
        ])
            .pipe(
                tap((t) => {
                    const uiState = t[0];
                    const selection = t[1];

                    this.menuService.updateMenu(uiState, selection.length);
                })
            )
        .subscribe();

        this.getFileState()
                .pipe(
                    map(f => f.workingDirectory),
                    distinct(), 
                    switchMap(f => this.apiService.readTrunkState(f)),
                    tap(t => this.exchangeContentService.update(t))
                )
                .subscribe();
    }

    private refreshUiState(): void {
        this.httpClient
            .get<UiState>(`api/ui/state`)
            .pipe(
                tap((t) => this.uiState$.next(t)),
                take(1)
            )
            .subscribe();

        // Open file
        this.menuService
            .getNextOpenFile()
            .pipe(
                filter((t) => !!t),
                switchMap((fileName) => this.apiService.fileOpen(fileName))
                //   tap(t => this.uiState$.next(t))
            )
            .subscribe();

        // New file
        this.menuService
            .getNextOpenFile()
            .pipe(
                filter((t) => t === ''), // new file
                switchMap((fileName) => this.apiService.fileNew())
                // tap(t => this.uiState$.next(t))
            )
            .subscribe();
    }

    public getUiState(): Observable<UiState> {
        return this.uiState$.asObservable();
    }

    public getFileState(): Observable<FileState> {
        return this.uiState$.asObservable().pipe(map((u) => u.fileState));
    }
}

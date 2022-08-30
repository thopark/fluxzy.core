import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { HttpTransportType, HubConnection, HubConnectionBuilder } from '@microsoft/signalr';
import { Observable, take } from 'rxjs';
import { ExchangeBrowsingState, ExchangeState, UiState } from '../core/models/auto-generated';

@Injectable({
  providedIn: 'root'
})
export class ApiService {
    private hubConnection: HubConnection ; 

    constructor(private httpClient: HttpClient) 
    { 
        this.hubConnection = new HubConnectionBuilder()
                              .withUrl('/xs'
                                    , {  // localhost from **AspNetCore3.1 service**
                                //skipNegotiation: true,
                                transport: HttpTransportType.LongPolling // TODO remove in production
                                }
                                )
                              .build();
                              
        this.hubConnection
            .start()
            .then(() => console.log('signalR connected'))
            .catch(err => console.log(`signalR error${err}`));
    }

    public registerEvent<T>(name : string, callback : (arg : T) => void ){
        this.hubConnection.on('uiUpdate', (data: T) => {
            callback(data);
        });
    }

    public getExchangeState(browsingState : ExchangeBrowsingState) : Observable<ExchangeState> {
         return this.httpClient.post<ExchangeState>(`api/trunk/read`, browsingState)
        .pipe(take(1)); 
    }

    public fileOpen(fileName : string) : Observable<UiState> {
        return this.httpClient.post<UiState>(`api/file/open`, { fileName })
            .pipe(
                take(1)
            );
    }

    public fileNew() : Observable<UiState> {
        return this.httpClient.post<UiState>(`api/file/new`, null)
            .pipe(
                take(1)
            );
    }
}

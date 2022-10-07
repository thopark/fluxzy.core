import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { HttpTransportType, HubConnection, HubConnectionBuilder } from '@microsoft/signalr';
import { Observable, take, map, tap } from 'rxjs';
import { ConnectionInfo, ExchangeBrowsingState, ExchangeState, FileContentDelete, FileSaveViewModel, FileState, FormatterContainerViewModel, FormattingResult, MultipartItem, SaveFileMultipartActionModel, TrunkState, UiState } from '../core/models/auto-generated';

@Injectable({
  providedIn: 'root'
})
// This service is responsible of delivering http service towards the .NET web service 
export class ApiService {
    private hubConnection: HubConnection ; 

    constructor(private httpClient: HttpClient) 
    { 
        this.hubConnection = new HubConnectionBuilder()
                              .withUrl('/xs', 
                                    { 
                                         // localhost from **AspNetCore3.1 service**
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
        this.hubConnection.on(name, (data: T) => {
            callback(data);
        });
    }

    public trunkDelete(fileContentDelete : FileContentDelete ) : Observable<TrunkState> {
        return this.httpClient.post<TrunkState>(`api/file-content/delete`, fileContentDelete)
            .pipe(
                take(1), 
                ) ; 
    }

    public trunkClear() : Observable<TrunkState> {
        return this.httpClient.delete<TrunkState>(`api/file-content`)
            .pipe(
                take(1), 
                ) ; 
    }

    public readTrunkState(workingDirectory: string) : Observable<TrunkState> {
         return this.httpClient.post<TrunkState>(`api/file-content/read`, null)
        .pipe(
            take(1)
            
            ); 
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

    public fileSave() : Observable<UiState> {
        return this.httpClient.post<UiState>(`api/file/save`, null)
            .pipe(
                take(1)
            );
    }
    public fileSaveAs(model : FileSaveViewModel) : Observable<UiState> {
        return this.httpClient.post<UiState>(`api/file/save-as`, model)
            .pipe(
                take(1)
            );
    }

    public proxyOn() : Observable<UiState> {
        return this.httpClient.post<UiState>(`api/proxy/on`, null)
            .pipe(
                take(1)
            );
    }

    public proxyOff() : Observable<UiState> {
        return this.httpClient.post<UiState>(`api/proxy/off`, null)
            .pipe(
                take(1)
            );
    }

    // public getRequestFormattingResults(exchangeId : number) : Observable<FormattingResult[]> {
    //     return this.httpClient.get<FormattingResult[]>(`api/producers/request/${exchangeId}`)
    //         .pipe(
    //             take(1)
    //         );
    // }

    // public getResponseFormattingResults(exchangeId : number) : Observable<FormattingResult[]> {
    //     return this.httpClient.get<FormattingResult[]>(`api/producers/response/${exchangeId}`)
    //         .pipe(
    //             take(1)
    //         );
    // }
    
    public getFormatters(exchangeId : number) : Observable<FormatterContainerViewModel> {
        return this.httpClient.get<FormatterContainerViewModel>(`api/producers/formatters/${exchangeId}`)
            .pipe(
                take(1)
            );
    }

    public exchangeSaveRequestBody(exchangeId: number, fileName : string) : Observable<FormattingResult[]> {
        return this.httpClient.post<FormattingResult[]>(`api/exchange/${exchangeId}/save-request-body`, {
            fileName : fileName
        }).pipe(take(1));
    }

    public exchangeSaveMultipartContent(exchangeId: number, fileName: string, model : MultipartItem) : Observable<FormattingResult[]> {
        let payload : SaveFileMultipartActionModel = {
            filePath : fileName,
            offset : model.offset, 
            length : model.length
        };

        return this.httpClient.post<FormattingResult[]>(`api/exchange/${exchangeId}/save-multipart-Content`, payload).pipe(take(1));
    }

    public connectionGet(connectionId: number) : Observable<ConnectionInfo> {
        return this.httpClient.get<ConnectionInfo>(`api/connection/${connectionId}`).pipe(take(1));
    }
}

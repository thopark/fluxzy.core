//     This code was generated by a Reinforced.Typings tool.
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.

export interface FileOpeningViewModel
{
	fileName: string;
}
export interface FileSaveViewModel
{
	fileName: string;
}
export interface UiState
{
	id: string;
	fileState: FileState;
	proxyState: ProxyState;
	systemProxyState: any;
	settingsHolder: FluxzySettingsHolder;
}
export interface ProxyState
{
	boundConnections: ProxyEndPoint[];
	onError: boolean;
	message?: string;
}
export interface ProxyEndPoint
{
	address: string;
	port: number;
}
export interface ProxyBindPoint
{
	endPoint: any;
	default: boolean;
}
export interface ArchivingPolicy
{
	type: number;
	directory: string;
	none: ArchivingPolicy;
}
export interface FileState
{
	identifier: string;
	workingDirectory: string;
	mappedFileFullPath?: string;
	mappedFileName?: string;
	unsaved: boolean;
	lastModification: Date;
	contentOperation: any;
}
export interface FluxzySettingsHolder
{
	startupSetting: FluxzySetting;
}
export interface FluxzySetting
{
	boundPoints: ProxyBindPoint[];
	boundPointsDescription: string;
	verbose: boolean;
	connectionPerHost: number;
	anticipatedConnectionPerHost: number;
	throttleKBytePerSecond: number;
	serverProtocols: number;
	throttleIntervalCheck: any;
	caCertificate: any;
	certificateCacheDirectory: string;
	autoInstallCertificate: boolean;
	checkCertificateRevocation: boolean;
	disableCertificateCache: boolean;
	byPassHost: string[];
	maxHeaderLength: number;
	archivingPolicy: ArchivingPolicy;
	alterationRules: any[];
}
export interface ExchangeState
{
	exchanges: ExchangeContainer[];
	startIndex: number;
	endIndex: number;
	totalCount: number;
}
export interface ExchangeBrowsingState
{
	startIndex: number;
	count: number;
	type: number;
}
export interface ExchangeContainer
{
	id: number;
	exchangeInfo: ExchangeInfo;
}
export interface ConnectionContainer
{
	id: number;
	connectionInfo: ConnectionInfo;
}
export interface TrunkState
{
	exchanges: ExchangeContainer[];
	connections: ConnectionContainer[];
	maxExchangeId: number;
	exchangesIndexer: { [key:number]: number };
	connectionsIndexer: { [key:number]: number };
}
export interface FileContentDelete
{
	identifiers: number[];
}
export interface ExchangeInfo
{
	id: number;
	connectionId: number;
	httpVersion: string;
	requestHeader: RequestHeaderInfo;
	responseHeader: ResponseHeaderInfo;
	metrics: ExchangeMetrics;
	fullUrl: string;
	knownAuthority: string;
	method: string;
	path: string;
	contentType: string;
	done: boolean;
	statusCode: number;
	egressIp: string;
	pending: boolean;
}
export interface RequestHeaderInfo
{
	method: string;
	scheme: string;
	path: string;
	authority: string;
	headers: HeaderFieldInfo[];
}
export interface ResponseHeaderInfo
{
	statusCode: number;
	headers: HeaderFieldInfo[];
}
export interface ExchangeMetrics
{
	receivedFromProxy: Date;
	retrievingPool: Date;
	requestHeaderSending: Date;
	requestHeaderSent: Date;
	requestBodySent: Date;
	responseHeaderStart: Date;
	responseHeaderEnd: Date;
	responseBodyStart: Date;
	responseBodyEnd: Date;
	remoteClosed: Date;
	createCertStart: Date;
	createCertEnd: Date;
	totalSent: number;
	totalReceived: number;
	localPort: number;
	localAddress: string;
}
export interface HeaderFieldInfo
{
	name: string;
	value: string;
	forwarded: boolean;
}
export interface ConnectionInfo
{
	id: number;
	authority: AuthorityInfo;
	sslInfo: SslInfo;
	requestProcessed: number;
	dnsSolveStart: Date;
	dnsSolveEnd: Date;
	tcpConnectionOpening: Date;
	tcpConnectionOpened: Date;
	sslNegotiationStart: Date;
	sslNegotiationEnd: Date;
	localPort: number;
	localAddress: string;
	remoteAddress: string;
}
export interface AuthorityInfo
{
	hostName: string;
	port: number;
	secure: boolean;
}
export interface SslInfo
{
	sslProtocol: number;
	remoteCertificateIssuer: string;
	remoteCertificateSubject: string;
	localCertificateSubject: string;
	localCertificateIssuer: string;
	negotiatedApplicationProtocol: string;
	keyExchangeAlgorithm: string;
	hashAlgorithm: number;
	cipherAlgorithm: number;
}

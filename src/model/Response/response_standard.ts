export interface ApiResponse <T=any> {
    statusCode: number,
    success: boolean,
    message: string,
    data?: T,
    changedRows?: number;
    [key: string]: any;
}
export interface apiResponse <T=any> {
    statusCode: number,
    success: boolean,
    message: string,
    data?: T,
    changedRows?: number;
}
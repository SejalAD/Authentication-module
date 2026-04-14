export function generateOtp(){
    return Math.floor(100000 + Math.random()* 900000).toString();
}


export function getOtpHtml(otp){
    return `
    <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; background-color: #f9f9f9; border-radius: 10px;">
    <h2 style="color: #333;">
        Your OTP Code
    </h2>
    <p style="font-size: 24px; color: #555; margin: 20px 0;">${otp}</p>
    <p style="font-size: 14px; color: #777;">
        This OTP is valid for 10 minutes. Please do not share it with anyone.
    </p>
</div>
    `;  

}
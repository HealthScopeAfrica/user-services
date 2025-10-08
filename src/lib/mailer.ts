// mailer.js
import nodemailer from "nodemailer";
import { Resend } from "resend";

// Reusable transporter instance
const transporter = nodemailer.createTransport({
	service: "gmail", // You can also use "smtp.gmail.com"
	auth: {
		user: process.env.GMAIL_USER, // your Gmail address
		pass: process.env.GMAIL_APP_PASSWORD, // generated app password
	},
});

// Send mail function
interface Email {
	to: string;
	subject: string;
	// text: string;
	html: string;
}
// export async function sendMail({ to, subject, text, html }: Email) {
// 	try {
// 		const info = await transporter.sendMail({
// 			from: `"Team HealthScope - <${process.env.GMAIL_USER}>`,
// 			to,
// 			subject,
// 			text,
// 			html,
// 		});

// 		console.log("✅ Email sent:", info.messageId);
// 		return info;
// 	} catch (error) {
// 		console.error("❌ Email error:", error);
// 		throw error;
// 	}
// }

const RESEND_API_KEY =
	process.env.HS_READER_KEY || "re_UaTwLrvL_3v6zci4KfBRqPD3GB1qyW3hm";
const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;

export const sendMail = async ({ to, subject, html }: Email) => {
	// Prefer Resend when configured
	if (resend) {
		try {
			const result: any = await resend.emails.send({
				from: "healthscope.team@gmail.com",
				to: [to],
				subject,
				html,
			});

			// SDK may return a shaped object or throw; handle both
			if (result && (result as any).error) {
				// Make error visible to callers
				console.error("Resend API returned error:", (result as any).error);
				throw new Error(JSON.stringify((result as any).error));
			}

			console.log("Email sent via Resend:", result);
			return result;
		} catch (err) {
			// Surface the error and fall back to SMTP if available
			console.error("Resend send error:", err);
		}
	} else {
		console.warn(
			"RESEND_API_KEY not set; skipping Resend and using SMTP fallback if configured"
		);
	}

	// Fallback to nodemailer SMTP if configured
	// if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
	// 	try {
	// 		console.log("falling back on nodemailer setup");
	// 		const info = await transporter.sendMail({
	// 			from: `"Team HealthScope" <${process.env.GMAIL_USER}>`,
	// 			to,
	// 			subject,
	// 			html,
	// 		});
	// 		console.log("Email sent via SMTP transporter:", info.messageId);
	// 		return info;
	// 	} catch (smtpErr) {
	// 		console.error("SMTP send error:", smtpErr);
	// 		throw smtpErr;
	// 	}
	// }

	// If we reach here, no provider succeeded
	// throw new Error(
	// 	"No email provider succeeded (Resend failed and SMTP not configured)"
	// );
};
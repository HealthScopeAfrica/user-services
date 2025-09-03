// mailer.js
import nodemailer from "nodemailer";

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
	text: string;
	html: string;
}
export async function sendMail({ to, subject, text, html }: Email) {
	try {
		const info = await transporter.sendMail({
			from: `"Team HealthScope - <${process.env.GMAIL_USER}>`,
			to,
			subject,
			text,
			html,
		});

		console.log("✅ Email sent:", info.messageId);
		return info;
	} catch (error) {
		console.error("❌ Email error:", error);
		throw error;
	}
}

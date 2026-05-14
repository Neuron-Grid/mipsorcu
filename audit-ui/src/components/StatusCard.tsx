import type { StatusCardProps } from "../types/ui";

export const StatusCard = ({ title, ok, details, errorCode }: StatusCardProps) => (
    <article class={ok ? "status-card status-card--ok" : "status-card status-card--failure"}>
        <div class="status-card__header">
            <h2>{title}</h2>
            <span>{ok ? "valid" : "failure"}</span>
        </div>
        <ul>
            {details.map((detail) => (
                <li key={detail}>{detail}</li>
            ))}
        </ul>
        {errorCode !== null && <p class="error-code">error_code={errorCode}</p>}
    </article>
);

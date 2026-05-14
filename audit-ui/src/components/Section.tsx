import type { SectionProps } from "../types/ui";

export const Section = ({ title, badge, children }: SectionProps) => (
    <section class="panel">
        <div class="panel__header">
            <h2>{title}</h2>
            <span class="badge">{badge}</span>
        </div>
        <div class="table-scroll">{children}</div>
    </section>
);

export default function Placeholder({ title }: { title: string }) {
  return (
    <div className="grid min-h-[60vh] place-items-center">
      <div className="card max-w-md p-8 text-center">
        <div className="eyebrow">Coming online</div>
        <h2 className="mt-2 font-display text-2xl font-bold text-paper">{title}</h2>
        <p className="mt-2 text-sm text-mist">This view is being wired up in a later build slice.</p>
      </div>
    </div>
  );
}

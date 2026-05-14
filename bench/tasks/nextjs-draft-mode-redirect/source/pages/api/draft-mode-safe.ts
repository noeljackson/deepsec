import { draftMode } from 'next/headers';
import { redirect } from 'next/navigation';

const ALLOWED = /^\/(?:posts|preview)(?:\/|$)/;

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const slug = searchParams.get('slug') || '/';

  if (!ALLOWED.test(slug)) {
    return new Response('Bad target', { status: 400 });
  }

  draftMode().enable();
  redirect(slug);
}
